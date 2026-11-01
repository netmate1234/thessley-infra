from __future__ import annotations

import base64
import hashlib
import os
import sqlite3
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from infra.thessley_ad_service.machine_registry import MachineRegistry
from infra.thessley_ad_service.phone_registry import PhoneRegistry
from infra.thessley_ad_service.protocol import canonical_phone_message, principal_id_from_sid


SID = "S-1-5-21-1719900462-4250469598-2954734011-1106"


def _setup(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    os.chmod(state, 0o700)
    database = state / "state.sqlite3"
    machines = MachineRegistry(database)
    phone = PhoneRegistry(database)
    now = time.time()

    machine_key = ec.generate_private_key(ec.SECP256R1())
    machine_spki = machine_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    code = machines.create_enrollment_code(now=now)
    machine_id = machines.enroll(
        code=code,
        machine_name="MARTIN-WM",
        public_key_spki_b64=base64.b64encode(machine_spki).decode("ascii"),
        now=now,
    )
    assert machine_id

    enrollment = phone.create_enrollment(
        machine_id=machine_id,
        sid=SID,
        username="martin",
        authority="THESSLEYLAB",
        now=now,
    )
    assert enrollment

    phone_key = ec.generate_private_key(ec.SECP256R1())
    phone_spki = phone_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_key = base64.b64encode(phone_spki).decode("ascii")
    message = canonical_phone_message(
        type_="enroll",
        request_id=enrollment["request_id"],
        machine_id=machine_id,
        principal_id=principal_id_from_sid(SID),
        principal_type="domain",
        authority="THESSLEYLAB",
        username="martin",
        context="enrollment",
        nonce=enrollment["nonce"],
        timestamp=int(now),
        action="register",
    )
    signature = phone_key.sign(message, ec.ECDSA(hashes.SHA256()))
    assert phone.submit_enrollment(
        request_id=enrollment["request_id"],
        public_key_spki_b64=public_key,
        label="SM-A528B",
        timestamp=int(now),
        signature_b64=base64.b64encode(signature).decode("ascii"),
        now=now,
    )

    digest = hashlib.sha256(phone_spki).digest()
    number = int.from_bytes(digest[:4], "big") % 1_000_000
    pairing_code = f"{number:06d}"[:3] + " " + f"{number:06d}"[3:]
    return database, machines, phone, machine_id, enrollment, public_key, pairing_code, now


def test_phone_key_activates_only_after_machine_code_confirmation(tmp_path):
    _db, _machines, phone, machine_id, enrollment, public_key, pairing_code, now = _setup(tmp_path)

    assert phone.enrollment_status(
        machine_id="f" * 32, request_id=enrollment["request_id"], now=now
    ) is None
    status = phone.enrollment_status(machine_id=machine_id, request_id=enrollment["request_id"], now=now)
    assert status is not None
    assert status["status"] == "ready"
    assert status["username"] == "martin"
    assert status["pairing_code"] == pairing_code
    # A key submitted without an attestation chain stays enrollable but is
    # reported as unverified, so the admin cannot mistake it for a hardware key.
    assert status["attestation_status"] == "unverified"

    assert phone.confirm_enrollment(
        machine_id=machine_id, request_id=enrollment["request_id"], pairing_code=pairing_code, now=now
    )
    confirmed = phone.wait_enrollment(enrollment["request_id"], timeout=1)
    assert confirmed and confirmed["status"] == "confirmed"
    assert phone.public_key_for(confirmed["credential_id"], machine_id, enrollment["principal_id"]) == public_key


def test_wrong_pairing_code_locks_enrollment_without_activating_key(tmp_path):
    database, _machines, phone, machine_id, enrollment, _public_key, pairing_code, now = _setup(tmp_path)
    wrong_code = "000 000" if pairing_code != "000 000" else "000 001"

    for _ in range(5):
        assert not phone.confirm_enrollment(
            machine_id=machine_id,
            request_id=enrollment["request_id"],
            pairing_code=wrong_code,
            now=now,
        )

    assert phone.enrollment_status(machine_id=machine_id, request_id=enrollment["request_id"], now=now) == {
        "status": "denied",
        "username": "martin",
    }
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM phone_credentials").fetchone()[0] == 0
