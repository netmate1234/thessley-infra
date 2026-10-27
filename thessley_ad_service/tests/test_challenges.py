from __future__ import annotations

import base64
import os
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from infra.thessley_ad_service.challenges import ChallengeStore
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
    phones = PhoneRegistry(database)
    now = time.time()

    machine_key = ec.generate_private_key(ec.SECP256R1())
    machine_public = machine_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    code = machines.create_enrollment_code(now=now)
    machine_id = machines.enroll(
        code=code,
        machine_name="MARTIN-WM",
        public_key_spki_b64=base64.b64encode(machine_public).decode("ascii"),
        now=now,
    )
    assert machine_id

    phone_key = ec.generate_private_key(ec.SECP256R1())
    phone_public = phone_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    principal_id = principal_id_from_sid(SID)
    credential_id = phones.enroll(
        machine_id=machine_id,
        principal_id=principal_id,
        public_key_spki_b64=base64.b64encode(phone_public).decode("ascii"),
        label="SM-A528B",
        now=now,
    )
    assert credential_id

    challenges = ChallengeStore(database, phones.public_key_for)
    request = challenges.create(
        machine_id=machine_id,
        sid=SID,
        username="martin",
        authority="THESSLEYLAB",
        context="interactive",
        now=now,
    )
    return challenges, machine_id, credential_id, principal_id, phone_key, request, now


def test_login_approval_requires_phone_signature_and_is_delivered_once(tmp_path):
    challenges, machine_id, credential_id, principal_id, phone_key, request, now = _setup(tmp_path)
    timestamp = int(now)
    message = canonical_phone_message(
        type_="login",
        request_id=request["request_id"],
        machine_id=machine_id,
        principal_id=principal_id,
        principal_type="domain",
        authority="THESSLEYLAB",
        username="martin",
        context="interactive",
        nonce=request["nonce"],
        timestamp=timestamp,
        action="approve",
    )
    signature = phone_key.sign(message, ec.ECDSA(hashes.SHA256()))

    assert challenges.respond(
        request_id=request["request_id"],
        credential_id=credential_id,
        action="approve",
        timestamp=timestamp,
        signature_b64=base64.b64encode(signature).decode("ascii"),
        now=now,
    )
    assert challenges.consume_result(machine_id=machine_id, request_id=request["request_id"], now=now) == {
        "status": "approved"
    }
    assert challenges.consume_result(machine_id=machine_id, request_id=request["request_id"], now=now) == {
        "status": "consumed"
    }


def test_unsigned_refusal_requires_the_qr_nonce_and_cannot_approve(tmp_path):
    challenges, machine_id, credential_id, _principal_id, _phone_key, request, now = _setup(tmp_path)
    timestamp = int(now)

    assert not challenges.respond(
        request_id=request["request_id"],
        credential_id=credential_id,
        action="deny",
        timestamp=timestamp,
        signature_b64=None,
        nonce="wrongnonce1234567890",
        now=now,
    )
    assert challenges.consume_result(machine_id=machine_id, request_id=request["request_id"], now=now) == {
        "status": "pending"
    }
    assert challenges.respond(
        request_id=request["request_id"],
        credential_id=credential_id,
        action="deny",
        timestamp=timestamp,
        signature_b64=None,
        nonce=request["nonce"],
        now=now,
    )
    assert challenges.consume_result(machine_id=machine_id, request_id=request["request_id"], now=now) == {
        "status": "denied"
    }
