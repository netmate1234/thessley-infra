import base64
import hashlib
import sqlite3

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils

from infra.thessley_ad_service.ad_logon_keys import AdLogonKeyRegistry
from infra.thessley_ad_service.challenges import ChallengeStore
from infra.thessley_ad_service.piv_signatures import PivSignatureStore
from infra.thessley_ad_service.protocol import principal_id_from_sid


MACHINE_ID = "a" * 32
SID = "S-1-5-21-100-200-300-1106"
PRINCIPAL_ID = principal_id_from_sid(SID)
CREDENTIAL_ID = "c" * 32
KEY_ID = "k" * 32
REQUEST_ID = "r" * 32
NOW = 1_800_000_000.0


def make_approved_request(path, *, key_type="ec"):
    key = (ec.generate_private_key(ec.SECP256R1()) if key_type == "ec"
           else rsa.generate_private_key(public_exponent=65537, key_size=2048))
    spki = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_key_hash = hashlib.sha256(spki).hexdigest()
    encoded_spki = base64.b64encode(spki).decode("ascii")

    logon_keys = AdLogonKeyRegistry(path)
    challenges = ChallengeStore(path, lambda *_args: None, logon_keys.active_key_matches_public_key)
    challenge = challenges.create(
        machine_id=MACHINE_ID, sid=SID, username="testuser", authority="THESSLEYLAB",
        context="interactive", now=NOW, piv_signing=True,
    )
    request_id = challenge["request_id"]
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            "UPDATE login_challenges SET status='approve',credential_id=?,response_at=?,delivered_at=? "
            "WHERE request_id=?",
            (CREDENTIAL_ID, NOW + 1, NOW + 1, request_id),
        )
        connection.execute(
            "INSERT INTO ad_logon_keys(key_id,request_id,principal_id,approval_credential_id,"
            "public_key_spki_b64,public_key_sha256,label,attestation_chain_json,attestation_status,"
            "created_at,revoked_at,revoked_by) VALUES(?,?,?,?,?,?,?,?,?,?,NULL,NULL)",
            (KEY_ID, "e" * 32, PRINCIPAL_ID, CREDENTIAL_ID, encoded_spki, public_key_hash,
             "PIV test key", "[]", "unverified", NOW),
        )
        connection.commit()
    finally:
        connection.close()
    return PivSignatureStore(path, logon_keys), challenges, key, request_id, public_key_hash


def test_phone_signature_is_bound_verified_and_returned_once(tmp_path):
    path = tmp_path / "state.sqlite3"
    store, _challenges, private_key, request_id, public_key_hash = make_approved_request(path)
    digest = hashlib.sha256(b"PIV GENERAL AUTHENTICATE test digest").digest()

    queued = store.create_for_machine(
        machine_id=MACHINE_ID, request_id=request_id,
        ad_logon_key_sha256=public_key_hash, digest=digest, now=NOW + 2,
    )
    assert queued is not None
    assert queued["status"] == "pending"

    phone_request = store.for_phone(
        request_id=request_id, credential_id=CREDENTIAL_ID,
        ad_logon_key_sha256=public_key_hash, now=NOW + 3,
    )
    assert phone_request is not None
    assert phone_request["status"] == "sign"
    assert phone_request["digest_b64"] == base64.b64encode(digest).decode("ascii")

    signature = private_key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    signature_b64 = base64.b64encode(signature).decode("ascii")
    assert store.complete_from_phone(
        request_id=request_id, sign_request_id=queued["sign_request_id"],
        credential_id=CREDENTIAL_ID, ad_logon_key_sha256=public_key_hash,
        signature_b64=signature_b64, now=NOW + 4,
    )
    result = store.result_for_machine(
        machine_id=MACHINE_ID, request_id=request_id,
        sign_request_id=queued["sign_request_id"], now=NOW + 5,
    )
    assert result == {"status": "signed", "signature_b64": signature_b64}


def test_rsa_piv_digestinfo_algorithms_are_bound_and_verified(tmp_path):
    cases = (
        ("RSA_SHA1", bytes.fromhex("3021300906052b0e03021a05000414"), hashes.SHA1),
        ("RSA_SHA256", bytes.fromhex("3031300d060960864801650304020105000420"), hashes.SHA256),
        ("RSA_SHA384", bytes.fromhex("3041300d060960864801650304020205000430"), hashes.SHA384),
        ("RSA_SHA512", bytes.fromhex("3051300d060960864801650304020305000440"), hashes.SHA512),
    )
    for index, (name, prefix, hash_type) in enumerate(cases):
        path = tmp_path / f"rsa-{index}.sqlite3"
        store, _challenges, private_key, request_id, public_key_hash = make_approved_request(
            path, key_type="rsa",
        )
        hasher = hashes.Hash(hash_type())
        hasher.update(b"Windows PIV signing input")
        raw_digest = hasher.finalize()
        digest_info = prefix + raw_digest
        queued = store.create_for_machine(
            machine_id=MACHINE_ID, request_id=request_id,
            ad_logon_key_sha256=public_key_hash, digest=digest_info, now=NOW + 2,
        )
        assert queued is not None
        phone_request = store.for_phone(
            request_id=request_id, credential_id=CREDENTIAL_ID,
            ad_logon_key_sha256=public_key_hash, now=NOW + 3,
        )
        assert phone_request["signature_algorithm"] == name
        assert base64.b64decode(phone_request["digest_b64"]) == digest_info

        signature = private_key.sign(
            raw_digest, padding.PKCS1v15(), utils.Prehashed(hash_type()),
        )
        assert store.complete_from_phone(
            request_id=request_id, sign_request_id=queued["sign_request_id"],
            credential_id=CREDENTIAL_ID, ad_logon_key_sha256=public_key_hash,
            signature_b64=base64.b64encode(signature).decode("ascii"), now=NOW + 4,
        )


def test_rsa_rejects_unrecognized_digestinfo(tmp_path):
    path = tmp_path / "rsa-invalid.sqlite3"
    store, _challenges, _private_key, request_id, public_key_hash = make_approved_request(
        path, key_type="rsa",
    )
    assert store.create_for_machine(
        machine_id=MACHINE_ID, request_id=request_id,
        ad_logon_key_sha256=public_key_hash, digest=b"not a DER DigestInfo" * 3, now=NOW + 2,
    ) is None


def test_wrong_phone_key_cannot_obtain_or_submit_signature(tmp_path):
    path = tmp_path / "state.sqlite3"
    store, _challenges, private_key, request_id, public_key_hash = make_approved_request(path)
    digest = hashlib.sha256(b"approved digest").digest()
    queued = store.create_for_machine(
        machine_id=MACHINE_ID, request_id=request_id,
        ad_logon_key_sha256=public_key_hash, digest=digest, now=NOW + 2,
    )
    assert queued is not None

    assert store.for_phone(
        request_id=request_id, credential_id=CREDENTIAL_ID,
        ad_logon_key_sha256="f" * 64, now=NOW + 3,
    ) == {"status": "pending"}
    signature = private_key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    assert not store.complete_from_phone(
        request_id=request_id, sign_request_id=queued["sign_request_id"],
        credential_id=CREDENTIAL_ID, ad_logon_key_sha256="f" * 64,
        signature_b64=base64.b64encode(signature).decode("ascii"), now=NOW + 4,
    )


def test_invalid_signature_and_expired_approval_fail_closed(tmp_path):
    path = tmp_path / "state.sqlite3"
    store, _challenges, private_key, request_id, public_key_hash = make_approved_request(path)
    digest = hashlib.sha256(b"approved digest").digest()
    queued = store.create_for_machine(
        machine_id=MACHINE_ID, request_id=request_id,
        ad_logon_key_sha256=public_key_hash, digest=digest, now=NOW + 2,
    )
    assert queued is not None
    wrong_digest_signature = private_key.sign(
        hashlib.sha256(b"different digest").digest(), ec.ECDSA(utils.Prehashed(hashes.SHA256())),
    )
    assert not store.complete_from_phone(
        request_id=request_id, sign_request_id=queued["sign_request_id"],
        credential_id=CREDENTIAL_ID, ad_logon_key_sha256=public_key_hash,
        signature_b64=base64.b64encode(wrong_digest_signature).decode("ascii"), now=NOW + 3,
    )
    assert store.for_phone(
        request_id=request_id, credential_id=CREDENTIAL_ID,
        ad_logon_key_sha256=public_key_hash, now=NOW + 182,
    ) == {"status": "expired"}
    assert store.result_for_machine(
        machine_id=MACHINE_ID, request_id=request_id,
        sign_request_id=queued["sign_request_id"], now=NOW + 182,
    ) == {"status": "expired"}


def test_approved_piv_challenge_survives_qr_expiry_for_signature_window(tmp_path):
    path = tmp_path / "state.sqlite3"
    _store, challenges, _private_key, request_id, _public_key_hash = make_approved_request(path)

    assert challenges.purge_expired(now=NOW + 100) == 0
    connection = sqlite3.connect(path)
    try:
        assert connection.execute(
            "SELECT 1 FROM login_challenges WHERE request_id=?", (request_id,),
        ).fetchone() == (1,)
    finally:
        connection.close()

    assert challenges.purge_expired(now=NOW + 182) == 1
