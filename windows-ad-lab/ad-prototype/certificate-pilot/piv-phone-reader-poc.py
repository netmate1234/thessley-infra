#!/usr/bin/env python3
"""Disposable Windows PIV-reader discovery POC over vsmartcard vpcd.

This is intentionally not a production smart card implementation. It exposes
one public PIV Authentication certificate and accepts only the disposable
test PIN 0000 so Windows can reach the signing request. GENERAL AUTHENTICATE
is logged and refused; no signature is forged and no private key is present.
The listener is a vpcd client and connects only to 127.0.0.1.
"""

from __future__ import annotations

import argparse
import pathlib
import socket
import struct
import time


PIV_AID = bytes.fromhex("A000000308000010000100")
PIV_AID_TRUNCATED = PIV_AID[:-2]
PIV_AUTH_CERT_TAG = bytes.fromhex("5FC105")
CHUID_TAG = bytes.fromhex("5FC102")
CCC_TAG = bytes.fromhex("5FC107")
DISCOVERY_TAG = bytes.fromhex("7E")
TEST_PIN_APDU = bytes.fromhex("002000800830303030FFFFFFFF")


def tlv(tag: int, value: bytes) -> bytes:
    tag_bytes = tag.to_bytes(max(1, (tag.bit_length() + 7) // 8), "big")
    if len(value) < 128:
        length = bytes((len(value),))
    else:
        size = (len(value).bit_length() + 7) // 8
        encoded = len(value).to_bytes(size, "big")
        length = bytes((0x80 | size,)) + encoded
    return tag_bytes + length + value


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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--certificate",
        type=pathlib.Path,
        default=pathlib.Path(r"C:\Users\Public\thessley-startmenutest-ad-logon.cer"),
    )
    parser.add_argument("--port", type=int, default=35963)
    parser.add_argument(
        "--log",
        type=pathlib.Path,
        default=pathlib.Path(r"C:\Users\Public\piv-phone-reader-poc.log"),
    )
    args = parser.parse_args()

    cert = args.certificate.read_bytes()
    if not 256 <= len(cert) <= 64 * 1024:
        raise SystemExit("certificate file size is outside the allowed POC range")

    def record(message: str) -> None:
        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with args.log.open("a", encoding="ascii") as log:
            log.write(f"{stamp} {message}\n")

    # PIV cert object: 53 { 70 certificate, 71 CertInfo=uncompressed,
    # FE zero-length LRC }. Do not publish it in 9C/9E certificate slots.
    auth_cert = tlv(0x53, tlv(0x70, cert) + tlv(0x71, b"\x00") + tlv(0xFE, b""))
    chuid = tlv(
        0x53,
        tlv(0x30, bytes(25))
        + tlv(0x34, bytes.fromhex("102030405060708090A0B0C0D0E0F001"))
        + tlv(0x35, b"20271030")
        + tlv(0xFE, b""),
    )
    ccc = tlv(
        0x53,
        bytes.fromhex(
            "F000F100F200F300F400F50110F600F700FA00FB00FC00FD00FE00"
        ),
    )
    discovery = tlv(0x7E, tlv(0x4F, PIV_AID) + tlv(0x5F2F, bytes.fromhex("4000")))
    objects = {
        CHUID_TAG: chuid,
        PIV_AUTH_CERT_TAG: auth_cert,
        CCC_TAG: ccc,
        DISCOVERY_TAG: discovery,
    }

    # NIST SP 800-73-5 Part 2: the SELECT APT's 4F is the full 11-byte AID;
    # 79 identifies the coexistent-application authority, and 06 has a single
    # zero value byte as specified in Table 5. This card has ECDSA P-256 only.
    apt = tlv(
        0x61,
        tlv(0x4F, PIV_AID)
        + tlv(0x79, tlv(0x4F, PIV_AID))
        + tlv(0x50, b"Thessley PIV POC")
        + tlv(0xAC, tlv(0x80, b"\x11") + tlv(0x06, b"\x00")),
    )

    record(
        "started; loopback-only vpcd client; cert-bytes="
        + str(len(cert))
        + "; PIV-AID="
        + PIV_AID.hex()
    )
    pending = b""
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
                    response = bytes.fromhex("6A82")
                    record("SELECT non-PIV AID " + selected.hex() + " -> 6A82")
            elif apdu[:4] == bytes.fromhex("00CB3FFF"):
                tag = requested_tag(apdu)
                if tag not in objects:
                    pending = b""
                    response = bytes.fromhex("6A82")
                    record("GET DATA unsupported " + (tag.hex() if tag else apdu.hex()) + " -> 6A82")
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
                response = bytes.fromhex("9000")
                record("disposable test PIN accepted; PIN value not logged")
            elif apdu[:4] == bytes.fromhex("00200080"):
                response = bytes.fromhex("63C0")
                record("VERIFY rejected; PIN value not logged")
            elif apdu[:2] == bytes.fromhex("0087"):
                response = bytes.fromhex("6A81")
                record("GENERAL AUTHENTICATE observed and refused; no signature implementation")
            else:
                response = bytes.fromhex("6A81")
                record("unsupported APDU " + apdu.hex() + " -> 6A81")

            send_frame(sock, response)


if __name__ == "__main__":
    raise SystemExit(main())
