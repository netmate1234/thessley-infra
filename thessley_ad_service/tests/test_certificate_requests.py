from __future__ import annotations

import hashlib
import base64
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from infra.thessley_ad_service.certificate_requests import (
    CertificateRequestError,
    validate_approved_csr,
)
from infra.thessley_ad_service.ad_logon_keys import AdLogonKeyRegistry
from infra.thessley_ad_service.challenges import ChallengeStore


PRINCIPAL_ID = "a" * 64


def _phone_csr() -> tuple[bytes, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    request = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Thessley AD Logon Key")]))
        .sign(key, hashes.SHA256())
    )
    der = request.public_bytes(serialization.Encoding.DER)
    return der, hashlib.sha256(der).hexdigest()


def test_phone_tee_csr_accepts_small_p256_der_and_reports_spki_digest():
    der, digest = _phone_csr()

    metadata = validate_approved_csr(der, digest)

    assert len(der) < 256
    assert metadata["public_key_algorithm"] == "ec-p256"
    assert len(metadata["public_key_spki_sha256"]) == 64


def test_phone_csr_requires_an_active_account_key_match(tmp_path):
    der, digest = _phone_csr()
    metadata = validate_approved_csr(der, digest)
    database = tmp_path / "state.sqlite3"
    registry = AdLogonKeyRegistry(database)
    request = x509.load_der_x509_csr(der)
    spki = request.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    connection = registry._connect()
    try:
        connection.execute(
            "INSERT INTO ad_logon_keys(key_id, request_id, principal_id, approval_credential_id, "
            "public_key_spki_b64, public_key_sha256, label, attestation_chain_json, attestation_status, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("k" * 32, "r" * 16, PRINCIPAL_ID, "c" * 32,
             base64.b64encode(spki).decode("ascii"), metadata["public_key_spki_sha256"],
             "test", "[]", "verified_tee", time.time()),
        )
    finally:
        connection.close()
    challenges = ChallengeStore(database, lambda *_args: None, registry.active_key_matches_public_key)

    accepted = challenges._validate_certificate_csr(PRINCIPAL_ID, der, digest)

    assert accepted == metadata
    try:
        challenges._validate_certificate_csr("b" * 64, der, digest)
    except CertificateRequestError:
        pass
    else:
        raise AssertionError("CSR for an unrelated principal was accepted")
    assert registry.revoke(key_id="k" * 32, administrator="test")
    try:
        challenges._validate_certificate_csr(PRINCIPAL_ID, der, digest)
    except CertificateRequestError:
        pass
    else:
        raise AssertionError("CSR remained accepted after its AD key was revoked")


def test_phone_csr_fails_closed_without_registered_key_lookup(tmp_path):
    der, digest = _phone_csr()
    challenges = ChallengeStore(tmp_path / "challenge.sqlite3", lambda *_args: None)

    try:
        challenges._validate_certificate_csr(PRINCIPAL_ID, der, digest)
    except CertificateRequestError:
        pass
    else:
        raise AssertionError("EC CSR was accepted without an account-key lookup")
