#!/usr/bin/env python3
"""Disposable Windows PIV-reader discovery POC over vsmartcard vpcd.

This is intentionally not a production smart card implementation. It exposes
one public PIV Authentication certificate and accepts only the disposable
test PIN 0000. GENERAL AUTHENTICATE is refused unless that PIN was verified;
in relay mode the card digest is signed by the enrolled phone key and checked
against this certificate before it is returned. No private key is stored on
Windows. The listener is a vpcd client and connects only to 127.0.0.1.
"""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import os
import pathlib
import re
import socket
import struct
import sys
import threading
import time
import uuid


PIV_AID = bytes.fromhex("A000000308000010000100")
PIV_AID_TRUNCATED = PIV_AID[:-2]
PIV_AUTH_CERT_TAG = bytes.fromhex("5FC105")
CARD_AUTH_CERT_TAG = bytes.fromhex("5FC101")
SIGN_CERT_TAG = bytes.fromhex("5FC10A")
KEY_MANAGEMENT_CERT_TAG = bytes.fromhex("5FC10B")
KEY_HISTORY_TAG = bytes.fromhex("5FC10C")
CHUID_TAG = bytes.fromhex("5FC102")
FINGERPRINTS_TAG = bytes.fromhex("5FC103")
SECURITY_OBJECT_TAG = bytes.fromhex("5FC106")
CCC_TAG = bytes.fromhex("5FC107")
FACIAL_IMAGE_TAG = bytes.fromhex("5FC108")
DISCOVERY_TAG = bytes.fromhex("7E")
TEST_PIN_APDU = bytes.fromhex("002000800830303030FFFFFFFF")
PIV_ECDSA_P256 = 0x11
PIV_RSA_2048 = 0x07
PIV_AUTH_KEY_REFERENCE = 0x9A
PIV_CONFIG_REGISTRY_PATH = r"SOFTWARE\Thessley\ADCredentialProvider\Users"


def consume_registry_request_id(user_sid: str) -> str | None:
    """Read and delete the SID-scoped one-use approval id."""
    if not isinstance(user_sid, str) or not re.fullmatch(r"S-1-(?:[0-9]+-)+[0-9]+", user_sid):
        return None
    try:
        import winreg
        path = PIV_CONFIG_REGISTRY_PATH + "\\" + user_sid
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0,
                            winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE
                            | winreg.KEY_WOW64_64KEY) as key:
            value, value_type = winreg.QueryValueEx(key, "PivPhoneRequestId")
            if (value_type != winreg.REG_SZ or not isinstance(value, str)
                    or not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", value)):
                return None
            winreg.DeleteValue(key, "PivPhoneRequestId")
        return value
    except (OSError, ImportError):
        return None


def tlv(tag: int, value: bytes) -> bytes:
    tag_bytes = tag.to_bytes(max(1, (tag.bit_length() + 7) // 8), "big")
    if len(value) < 128:
        length = bytes((len(value),))
    else:
        size = (len(value).bit_length() + 7) // 8
        encoded = len(value).to_bytes(size, "big")
        length = bytes((0x80 | size,)) + encoded
    return tag_bytes + length + value


def lab_fasc_n(certificate: bytes) -> bytes:
    """Make a unique, syntactically valid non-federal FASC-N for this POC card."""
    credential = int.from_bytes(hashlib.sha256(certificate).digest()[:4], "big") % 1_000_000
    fields = (
        "B" + "9999" + "D" + "0001" + "D" + f"{credential:06d}"
        + "D" + "0" + "D" + "1" + "D" + "0000000001"
        + "3" + "0001" + "5" + "F"
    )
    if len(fields) != 39:
        raise ValueError("internal FASC-N field length is invalid")
    values = {"B": 0xB, "D": 0xD, "F": 0xF}
    values.update({str(value): value for value in range(10)})
    bits: list[int] = []
    for char in fields:
        value = values[char]
        nibble = [(value >> bit) & 1 for bit in range(4)]
        bits.extend(nibble + [1 - (sum(nibble) % 2)])
    lrc = sum((sum(bits[column::5]) % 2) << column for column in range(4))
    nibble = [(lrc >> bit) & 1 for bit in range(4)]
    bits.extend(nibble + [1 - (sum(nibble) % 2)])
    return bytes(
        sum(bit << (7 - offset % 8) for offset, bit in enumerate(bits[start : start + 8]))
        for start in range(0, 200, 8)
    )


def read_exact(sock: socket.socket, count: int) -> bytes:
    result = bytearray()
    while len(result) < count:
        chunk = sock.recv(count - len(result))
        if not chunk:
            raise EOFError("vpcd disconnected")
        result.extend(chunk)
    return bytes(result)


def send_frame(sock: socket.socket, payload: bytes) -> None:
    if len(payload) > 65535:
        raise ValueError("vpcd frame exceeds 16-bit length")
    sock.sendall(struct.pack(">H", len(payload)) + payload)


def requested_tag(apdu: bytes) -> bytes | None:
    if apdu[:4] != bytes.fromhex("00CB3FFF"):
        return None
    # GET DATA carries 5C <tag-length> <BER-TLV tag> in its data field.
    marker = apdu.find(b"\x5c", 4)
    if marker < 0 or marker + 2 >= len(apdu):
        return None
    length = apdu[marker + 1]
    if length == 0 or marker + 2 + length > len(apdu):
        return None
    return apdu[marker + 2 : marker + 2 + length]


def apdu_data(apdu: bytes) -> tuple[int, int, int, bytes] | None:
    """Decode a short or extended GENERAL AUTHENTICATE APDU strictly."""
    if len(apdu) < 5 or apdu[1] != 0x87 or apdu[0] not in (0x00, 0x10):
        return None
    cla, algorithm, key_reference = apdu[0], apdu[2], apdu[3]
    if apdu[4] != 0:
        lc = apdu[4]
        if len(apdu) not in (5 + lc, 6 + lc):
            return None
        body = apdu[5:5 + lc]
        if len(apdu) == 6 + lc and apdu[-1] != 0:
            return None
        return cla, algorithm, key_reference, body
    if len(apdu) < 7:
        return None
    lc = int.from_bytes(apdu[5:7], "big")
    if not lc or len(apdu) not in (7 + lc, 9 + lc):
        return None
    body = apdu[7:7 + lc]
    if len(apdu) == 9 + lc and apdu[-2:] != b"\x00\x00":
        return None
    return cla, algorithm, key_reference, body


def ber_length(data: bytes, offset: int) -> tuple[int, int] | None:
    """Read a canonical, definite BER length; return (length, next offset)."""
    if offset >= len(data):
        return None
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    count = first & 0x7F
    if count == 0 or count > 4 or offset + count > len(data):
        return None
    if data[offset] == 0:
        return None
    length = int.from_bytes(data[offset:offset + count], "big")
    # Reject long-form encodings for values that have a shorter canonical form.
    if length < 0x80 or (count > 1 and length < (1 << (8 * (count - 1)))):
        return None
    return length, offset + count


_RSA_DIGEST_INFO = {
    bytes.fromhex("3021300906052b0e03021a05000414"): ("RSA_SHA1", 20),
    bytes.fromhex("3031300d060960864801650304020105000420"): ("RSA_SHA256", 32),
    bytes.fromhex("3041300d060960864801650304020205000430"): ("RSA_SHA384", 48),
    bytes.fromhex("3051300d060960864801650304020305000440"): ("RSA_SHA512", 64),
}


def _rsa_verify_args(digest_info: bytes):
    """Return the algorithm-bound RSA PKCS#1 v1.5 verification arguments."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, utils

    for prefix, (name, digest_length) in _RSA_DIGEST_INFO.items():
        if digest_info.startswith(prefix) and len(digest_info) == len(prefix) + digest_length:
            algorithm = {
                "RSA_SHA1": hashes.SHA1,
                "RSA_SHA256": hashes.SHA256,
                "RSA_SHA384": hashes.SHA384,
                "RSA_SHA512": hashes.SHA512,
            }[name]()
            digest = digest_info[len(prefix):]
            return digest, padding.PKCS1v15(), utils.Prehashed(algorithm)
    raise ValueError("unsupported RSA DigestInfo")


def ga_digest(body: bytes, algorithm: int, diagnostics: list[str] | None = None) -> bytes | None:
    """Extract a constrained hash input from a PIV GA template.

    ECDSA relays a SHA-256 digest. RSA relays only a recognized DER DigestInfo,
    so the phone signs the exact PKCS#1 v1.5 input requested by Windows.
    """
    def reject(reason: str) -> None:
        if diagnostics is not None:
            diagnostics.append(reason)
        return None

    if len(body) < 4 or body[0] != 0x7C:
        return reject("outer-tag-or-size")
    outer = ber_length(body, 1)
    if outer is None:
        return reject("outer-length")
    outer_length, cursor = outer
    if outer_length != len(body) - cursor:
        return reject("outer-size-mismatch")
    digest, encoded = None, None
    fields: list[str] = []
    while cursor < len(body):
        tag = body[cursor]
        item = ber_length(body, cursor + 1)
        if item is None:
            return reject("field-length")
        size, value_offset = item
        cursor = value_offset
        if cursor + size > len(body):
            return reject("field-truncated")
        value = body[cursor:cursor + size]
        cursor += size
        fields.append(f"{tag:02x}:{size}")
        if tag == 0x82 and size == 0:
            continue
        if tag == 0x81 and size == 32 and digest is None:
            digest = value
        elif tag == 0x81 and algorithm == PIV_RSA_2048 and encoded is None:
            encoded = value
        else:
            return reject("fields=" + ",".join(fields))
    if algorithm == PIV_ECDSA_P256:
        return digest if digest is not None else reject("fields=" + ",".join(fields))
    if algorithm != PIV_RSA_2048 or encoded is None or len(encoded) != 256:
        return reject("rsa-block-size-or-algorithm;fields=" + ",".join(fields))
    # The reader supplies the complete EMSA-PKCS1-v1_5 block. Relay only the
    # canonical DigestInfo forms below; reject arbitrary RSA private operations.
    if not encoded.startswith(b"\x00\x01"):
        return reject("rsa-padding-header;fields=" + ",".join(fields))
    separator = encoded.find(b"\x00", 2)
    if separator < 10 or any(byte != 0xFF for byte in encoded[2:separator]):
        return reject("rsa-padding-separator;fields=" + ",".join(fields))
    digest_info = encoded[separator + 1 :]
    if not any(digest_info.startswith(prefix) and len(digest_info) == len(prefix) + digest_len
               for prefix, (_name, digest_len) in _RSA_DIGEST_INFO.items()):
        return reject(
            "rsa-digest-info;fields=" + ",".join(fields)
            + f";separator={separator};payload-bytes={len(digest_info)}"
        )
    return digest_info


def accepts_test_pin(apdu: bytes) -> bool:
    """Only accept the disposable test PIN APDU; never inspect or log other PINs."""
    return apdu == TEST_PIN_APDU


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--certificate",
        type=pathlib.Path,
        default=pathlib.Path(r"C:\Users\Public\thessley-startmenutest-ad-logon.cer"),
    )
    parser.add_argument("--port", type=int, default=35963)
    parser.add_argument(
        "--no-compress-certificate",
        action="store_true",
        help="diagnostic: send the DER certificate uncompressed even above 1856 bytes",
    )
    parser.add_argument(
        "--chuid-signature",
        type=pathlib.Path,
        help="optional detached CMS signature for the exact test CHUID fields",
    )
    parser.add_argument("--request-id", help="approved interactive AD login request id")
    parser.add_argument("--user-sid", help="read the one-use active PIV request id from the machine registry")
    parser.add_argument("--ad-logon-key-sha256", help="expected phone AD-key SPKI SHA-256")
    parser.add_argument(
        "--log",
        type=pathlib.Path,
        default=pathlib.Path(r"C:\Users\Public\piv-phone-reader-poc.log"),
    )
    args = parser.parse_args()

    cert = args.certificate.read_bytes()
    if not 256 <= len(cert) <= 64 * 1024:
        raise SystemExit("certificate file size is outside the allowed POC range")
    relay_enabled = args.request_id is not None or args.user_sid is not None or args.ad_logon_key_sha256 is not None
    # The no-relay discovery mode predates the RSA relay and retains its
    # original P-256 fixture. Relay mode replaces this from the actual cert.
    piv_auth_algorithm = PIV_ECDSA_P256
    if relay_enabled:
        if (args.request_id is None and args.user_sid is None):
            raise SystemExit("signature relay requires --request-id or --user-sid")
        if args.request_id is not None and not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", args.request_id):
            raise SystemExit("invalid approval request id")
        if args.user_sid is not None and not re.fullmatch(r"S-1-(?:[0-9]+-)+[0-9]+", args.user_sid):
            raise SystemExit("invalid AD user SID")
        if args.ad_logon_key_sha256 is not None and not re.fullmatch(r"[a-f0-9]{64}", args.ad_logon_key_sha256):
            raise SystemExit("invalid AD logon-key SHA-256")
        # The installer runs this helper with Python isolated mode (-I), so
        # the app's private dependencies are not on sys.path by default. Add
        # the vendor directory before parsing the certificate with
        # cryptography; adding it later only before importing ad_agent is too
        # late for this first use.
        program_data = pathlib.Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData"))
        vendor = program_data / "ThessleyPamWin" / "app" / "vendor"
        sys.path.insert(0, str(vendor))
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import ec, rsa
            try:
                certificate = x509.load_der_x509_certificate(cert)
            except ValueError:
                certificate = x509.load_pem_x509_certificate(cert)
                # PIV's 0x70 certificate object contains the encoded X.509
                # certificate, not PEM armor. Keep accepting PEM files from
                # certreq, but normalize them before building any card data.
                cert = certificate.public_bytes(serialization.Encoding.DER)
            certificate_public_key = certificate.public_key()
            spki = certificate_public_key.public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        except (ImportError, ValueError, TypeError) as exc:
            raise SystemExit("could not parse the public PIV certificate") from exc
        is_p256 = (isinstance(certificate_public_key, ec.EllipticCurvePublicKey)
                   and certificate_public_key.curve.name == "secp256r1")
        is_rsa2048 = isinstance(certificate_public_key, rsa.RSAPublicKey) and certificate_public_key.key_size == 2048
        if not (is_p256 or is_rsa2048):
            raise SystemExit("the relay accepts only enrolled P-256 or RSA-2048 AD logon keys")
        piv_auth_algorithm = PIV_ECDSA_P256 if is_p256 else PIV_RSA_2048
        cert_key_hash = hashlib.sha256(spki).hexdigest()
        if args.ad_logon_key_sha256 and cert_key_hash != args.ad_logon_key_sha256:
            raise SystemExit("PIV certificate key does not match the expected enrolled AD key")
        args.ad_logon_key_sha256 = cert_key_hash
        program_data = pathlib.Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData"))
        source_root = pathlib.Path(__file__).resolve().parents[1]
        package_roots = (
            source_root,
            program_data / "ThessleyPamWin" / "ad-prototype",
        )
        package_root = next(
            (root for root in package_roots if (root / "thessley_pam_win" / "ad_agent.py").is_file()),
            None,
        )
        if package_root is None:
            raise SystemExit("the installed Thessley AD agent package could not be located")
        sys.path.insert(0, str(package_root))
        vendor = program_data / "ThessleyPamWin" / "app" / "vendor"
        sys.path.insert(1, str(vendor))
        try:
            from thessley_pam_win import ad_agent
        except ImportError as exc:
            raise SystemExit("the installed Thessley AD agent is required for phone-sign relay") from exc

    def consume_request_id() -> str | None:
        """Consume the active login id when Windows begins card signing.

        ReportResult can run before the smart-card stack sends GENERAL
        AUTHENTICATE. Keep the id until this point, then delete it before the
        network relay so another APDU cannot start a second phone-sign job.
        The phone service independently binds the signature to the approved
        login, enrolled key, and exact digest, with a short expiry.
        """
        if args.request_id is not None:
            return args.request_id
        if args.user_sid is None:
            return None
        return consume_registry_request_id(args.user_sid)

    def record(message: str) -> None:
        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with args.log.open("a", encoding="ascii") as log:
            log.write(f"{stamp} {message}\n")

    # PIV cert object: 53 { 70 certificate, 71 CertInfo, FE zero-length LRC }.
    # Keep the authentication certificate within the recommended 1856-byte
    # object size when gzip can do so. CertInfo 0x01 denotes GZIP per SP 800-73.
    cert_info = b"\x00"
    cert_object_bytes = cert
    if len(cert) > 1856 and not args.no_compress_certificate:
        compressed_cert = gzip.compress(cert, mtime=0)
        if len(compressed_cert) < len(cert):
            cert_object_bytes = compressed_cert
            cert_info = b"\x01"
    auth_cert = tlv(
        0x53,
        tlv(0x70, cert_object_bytes) + tlv(0x71, cert_info) + tlv(0xFE, b""),
    )
    issuer_signature = args.chuid_signature.read_bytes() if args.chuid_signature else b""
    if len(issuer_signature) > 8192:
        raise SystemExit("CHUID CMS signature exceeds the POC size limit")
    chuid = tlv(
        0x53,
        tlv(0x30, lab_fasc_n(cert))
        + tlv(0x34, uuid.uuid5(uuid.NAMESPACE_URL, hashlib.sha256(cert).hexdigest()).bytes)
        + tlv(0x35, b"20271030")
        # Current SP 800-73-5 requires an issuer CMS signature. The empty
        # default is only a discovery diagnostic; a supplied signature must
        # cover these exact encoded CHUID fields.
        + tlv(0x3E, issuer_signature)
        + tlv(0xFE, b""),
    )
    # CCC F0 is not an empty placeholder: it contains the 5-byte RID and a
    # 16-byte card identifier. Windows' PIV minidriver uses the card identity
    # while establishing its per-card key-container mapping. Keep it stable
    # for this certificate so a relay restart does not appear as a new card.
    card_identifier = bytes.fromhex("A000000116") + uuid.uuid5(
        uuid.NAMESPACE_URL, hashlib.sha256(cert).hexdigest()
    ).bytes
    ccc = tlv(
        0x53,
        tlv(0xF0, card_identifier)
        + tlv(0xF1, b"\x21")
        + tlv(0xF2, b"\x21")
        + tlv(0xF3, b"\x00")
        + tlv(0xF4, b"\x00")
        + tlv(0xF5, b"\x10")
        + tlv(0xF6, b"\x00")
        + tlv(0xF7, b"\x00")
        + tlv(0xFA, b"")
        + tlv(0xFB, b"")
        + tlv(0xFC, b"")
        + tlv(0xFD, b"")
        + tlv(0xFE, b""),
    )
    discovery = tlv(0x7E, tlv(0x4F, PIV_AID) + tlv(0x5F2F, bytes.fromhex("4000")))
    objects = {
        CHUID_TAG: chuid,
        PIV_AUTH_CERT_TAG: auth_cert,
        # This lab card exercises only PIV Authentication key 9A. Keep the
        # other certificate slots explicitly empty instead of claiming that
        # their data objects do not exist. Windows probes 9C/9D/9E while
        # resolving the PIV card's key containers.
        CARD_AUTH_CERT_TAG: tlv(0x53, b""),
        SIGN_CERT_TAG: tlv(0x53, b""),
        KEY_MANAGEMENT_CERT_TAG: tlv(0x53, b""),
        KEY_HISTORY_TAG: tlv(0x53, b""),
        FINGERPRINTS_TAG: tlv(0x53, b""),
        SECURITY_OBJECT_TAG: tlv(0x53, b""),
        CCC_TAG: ccc,
        FACIAL_IMAGE_TAG: tlv(0x53, b""),
        DISCOVERY_TAG: discovery,
    }

    # NIST SP 800-73-5 Part 2: the SELECT APT's 4F is the full 11-byte AID;
    # 79 identifies the coexistent-application authority, and 06 has a single
    # zero value byte as specified in Table 5. Advertise the algorithm that
    # matches the actual PIV Authentication certificate and signing key.
    apt = tlv(
        0x61,
        tlv(0x4F, bytes.fromhex("000010000100"))
        + tlv(0x79, tlv(0x4F, PIV_AID_TRUNCATED))
        + tlv(0x50, b"Thessley PIV POC")
        + tlv(0xAC, tlv(0x80, bytes((piv_auth_algorithm,))) + tlv(0x06, b"\x00")),
    )

    record(
        "started; loopback-only vpcd client; cert-bytes="
        + str(len(cert))
        + "; PIV-AID="
        + PIV_AID.hex()
    )
    pending = b""
    pending_ga = bytearray()
    pin_verified = False
    ga_attempt = 0
    with socket.create_connection(("127.0.0.1", args.port), timeout=10) as sock:
        sock.settimeout(60)
        while True:
            size = struct.unpack(">H", read_exact(sock, 2))[0]
            apdu = read_exact(sock, size)

            if size == 1:
                if apdu[0] == 4:
                    atr = bytes.fromhex(
                        "3B 9F 95 81 31 FE 9F 00 66 46 53 05 10 00 11 71 DF 00 00 00 00 00 02"
                    )
                    send_frame(sock, atr)
                    record("ATR requested")
                else:
                    if apdu[0] in (0, 2):  # power-off or reset clears card security state
                        pin_verified = False
                        pending = b""
                        pending_ga.clear()
                    record("control " + apdu.hex())
                continue

            response: bytes
            if len(apdu) >= 5 and apdu[:4] == bytes.fromhex("00A40400"):
                lc = apdu[4]
                selected = apdu[5 : 5 + lc]
                if selected in (PIV_AID, PIV_AID_TRUNCATED):
                    pending = b""
                    response = apt + bytes.fromhex("9000")
                    record("SELECT PIV AID " + selected.hex() + " -> 9000 apt=" + apt.hex())
                else:
                    pin_verified = False
                    response = bytes.fromhex("6A82")
                    record("SELECT non-PIV AID " + selected.hex() + " -> 6A82")
            elif apdu[:4] == bytes.fromhex("00CB3FFF"):
                tag = requested_tag(apdu)
                if tag not in objects:
                    pending = b""
                    # 6A88 means the referenced data object does not exist.
                    # 6A82 means the PIV application itself was not found; using
                    # it here can make Windows treat this as an app-selection
                    # failure instead of an optional object being absent.
                    response = bytes.fromhex("6A88")
                    record("GET DATA unsupported " + (tag.hex() if tag else apdu.hex()) + " -> 6A88")
                else:
                    pending = objects[tag]
                    chunk, pending = pending[:255], pending[255:]
                    sw = bytes((0x61, min(len(pending), 255))) if pending else bytes.fromhex("9000")
                    response = chunk + sw
                    record("GET DATA " + tag.hex() + " -> " + sw.hex() + " object-bytes=" + str(len(objects[tag])))
            elif apdu[:2] == bytes.fromhex("00C0"):
                le = apdu[-1] or 256
                chunk, pending = pending[: min(le, 255)], pending[min(le, 255) :]
                sw = bytes((0x61, min(len(pending), 255))) if pending else bytes.fromhex("9000")
                response = chunk + sw
                record("GET RESPONSE -> " + sw.hex() + " remaining=" + str(len(pending)))
            elif apdu == TEST_PIN_APDU:
                pin_verified = True
                response = bytes.fromhex("9000")
                record("disposable test PIN accepted; PIN value not logged")
            elif apdu[:4] == bytes.fromhex("00200080"):
                pin_verified = False
                response = bytes.fromhex("63C0")
                record("VERIFY rejected; PIN value not logged")
            elif len(apdu) >= 2 and apdu[1] == 0x87:
                ga_attempt += 1
                parsed = apdu_data(apdu)
                digest = None
                ga_diagnostics: list[str] = []
                if not pin_verified:
                    pending_ga.clear()
                    response = bytes.fromhex("6982")
                    record("GENERAL AUTHENTICATE refused; test PIN not verified")
                elif parsed is not None:
                    cla, algorithm, key_reference, fragment = parsed
                    key_matches_algorithm = (
                        (algorithm == PIV_ECDSA_P256 and isinstance(certificate_public_key, ec.EllipticCurvePublicKey))
                        or (algorithm == PIV_RSA_2048 and isinstance(certificate_public_key, rsa.RSAPublicKey))
                    )
                    if (key_matches_algorithm and key_reference == PIV_AUTH_KEY_REFERENCE
                            and len(pending_ga) + len(fragment) <= 4096):
                        pending_ga.extend(fragment)
                        if cla & 0x10:
                            response = bytes.fromhex("9000")
                            record("GENERAL AUTHENTICATE chained fragment accepted; fragment-bytes="
                                   + str(len(fragment)) + "; total-bytes=" + str(len(pending_ga)))
                            send_frame(sock, response)
                            continue
                        digest = ga_digest(bytes(pending_ga), algorithm, ga_diagnostics) if relay_enabled else None
                    pending_ga.clear()
                if digest is None:
                    response = bytes.fromhex("6A81")
                    if parsed is None:
                        record("GENERAL AUTHENTICATE refused; malformed or unsupported APDU")
                    else:
                        record("GENERAL AUTHENTICATE refused; alg=" + format(parsed[1], "02x")
                               + " key=" + format(parsed[2], "02x")
                               + " data-bytes=" + str(len(parsed[3]))
                               + ("; " + ga_diagnostics[0] if ga_diagnostics else ""))
                else:
                    request_id = consume_request_id()
                    signature = None
                    if request_id is None:
                        record("GENERAL AUTHENTICATE refused; no unconsumed PIV request id; attempt="
                               + str(ga_attempt))
                    else:
                        record("GENERAL AUTHENTICATE consumed one-use PIV request id; relay started; attempt="
                               + str(ga_attempt))
                        try:
                            queued = ad_agent.start_piv_signature(
                                request_id, args.ad_logon_key_sha256, digest)
                            signature = ad_agent.wait_piv_signature(
                                request_id, queued["sign_request_id"], digest,
                                threading.Event(), timeout=75)
                            if signature is not None:
                                from cryptography.hazmat.primitives import hashes
                                from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
                                if isinstance(certificate_public_key, ec.EllipticCurvePublicKey):
                                    certificate_public_key.verify(
                                        signature, digest,
                                        ec.ECDSA(utils.Prehashed(hashes.SHA256())))
                                elif isinstance(certificate_public_key, rsa.RSAPublicKey):
                                    certificate_public_key.verify(signature, *_rsa_verify_args(digest))
                                else:
                                    signature = None
                        except Exception as exc:
                            signature = None
                            # AgentError messages are fixed protocol/status text
                            # from our client or service; include the reason so
                            # a rejected request is distinguishable from a
                            # timeout. Never log the digest or signature bytes.
                            detail = " ".join(str(exc).split())[:180]
                            record("phone-sign relay failed: " + type(exc).__name__
                                   + ("; reason=" + detail if detail else "")
                                   + "; attempt=" + str(ga_attempt))
                    valid_size = (
                        isinstance(certificate_public_key, ec.EllipticCurvePublicKey)
                        and 64 <= len(signature or b"") <= 72
                    ) or (
                        isinstance(certificate_public_key, rsa.RSAPublicKey)
                        and len(signature or b"") == 256
                    )
                    if signature is None or not valid_size:
                        response = bytes.fromhex("6400")
                        record("GENERAL AUTHENTICATE timed out or was refused; no signature returned; attempt="
                               + str(ga_attempt))
                    else:
                        response_data = tlv(0x7C, tlv(0x82, signature))
                        # BixVReader/Windows can reject the full RSA-2048 PIV
                        # response (266 bytes including SW1/SW2) with
                        # ERROR_INSUFFICIENT_BUFFER. PIV response chaining
                        # keeps each transmit short; the minidriver retrieves
                        # the remaining TLV bytes with GET RESPONSE (00 C0).
                        first_chunk_size = 240
                        if len(response_data) > first_chunk_size:
                            pending = response_data[first_chunk_size:]
                            remaining = min(len(pending), 255)
                            response = response_data[:first_chunk_size] + bytes((0x61, remaining))
                            record("GENERAL AUTHENTICATE returned verified phone signature; response chained; "
                                   + "first-fragment-bytes=" + str(first_chunk_size)
                                   + "; remaining-bytes=" + str(len(pending))
                                   + "; digest omitted; attempt=" + str(ga_attempt))
                        else:
                            response = response_data + bytes.fromhex("9000")
                            record("GENERAL AUTHENTICATE returned verified phone signature; digest omitted; attempt="
                                   + str(ga_attempt))
            else:
                response = bytes.fromhex("6A81")
                record("unsupported APDU " + apdu.hex() + " -> 6A81")

            send_frame(sock, response)


if __name__ == "__main__":
    raise SystemExit(main())
