"""HTTP route factory for the first standalone AD service operation."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .machine_registry import MachineRegistry
    from .machine_auth import ReplayGuard


MACHINE_ENROLL_PATH = "/thessley-ad/v1/machines/enroll"
MACHINE_AUTH_PATH = "/thessley-ad/v1/machines/authenticate"


def machine_enrollment_route(registry: "MachineRegistry"):
    """Return a raw-body listener route for one-time machine enrollment.

    Enrollment is authorized by the short-lived, single-use code. The code
    itself must have been created by an admin-authorized local caller. The
    machine display name is metadata only and grants no AD rights.
    """
    from thessley_pam.listener import RawBodyRoute

    def handle(_client_ip: str, body: dict, _raw_body: bytes, auth_headers: dict[str, str]):
        if auth_headers:
            return 400, {"result": "error", "message": "Do not send machine-auth headers to enrollment."}
        if set(body) != {"code", "machine_name", "public_key_spki_b64"}:
            return 400, {"result": "error", "message": "Invalid enrollment request."}
        try:
            machine_id = registry.enroll(
                code=body["code"],
                machine_name=body["machine_name"],
                public_key_spki_b64=body["public_key_spki_b64"],
            )
        except (TypeError, ValueError):
            machine_id = None
        if machine_id is None:
            return 403, {"result": "error", "message": "Enrollment code is invalid or expired."}
        return 201, {"result": "enrolled", "machine_id": machine_id}

    return RawBodyRoute(handle)


def machine_authentication_route(registry: "MachineRegistry", replay_guard: "ReplayGuard"):
    """Return an authenticated machine liveness endpoint for protocol bring-up."""
    from thessley_pam.listener import RawBodyRoute

    from .machine_auth import verify_request

    def handle(_client_ip: str, body: dict, raw_body: bytes, auth_headers: dict[str, str]):
        expected = {
            "x-thessley-machine-id", "x-thessley-timestamp", "x-thessley-nonce", "x-thessley-signature"
        }
        if set(auth_headers) != expected or body != {}:
            return 400, {"result": "error", "message": "Invalid machine authentication request."}
        machine_id = auth_headers["x-thessley-machine-id"]
        try:
            timestamp = int(auth_headers["x-thessley-timestamp"])
        except (TypeError, ValueError):
            return 401, {"result": "error", "message": "Machine authentication failed."}
        public_key = registry.public_key(machine_id)
        if public_key is None or not verify_request(
            public_key_spki_b64=public_key,
            signature_b64=auth_headers["x-thessley-signature"],
            method="POST",
            path=MACHINE_AUTH_PATH,
            machine_id=machine_id,
            timestamp=timestamp,
            nonce=auth_headers["x-thessley-nonce"],
            body=raw_body,
            replay_guard=replay_guard,
        ):
            return 401, {"result": "error", "message": "Machine authentication failed."}
        return 200, {"result": "authenticated", "machine_id": machine_id}

    return RawBodyRoute(handle)


def create_routes(registry: "MachineRegistry", replay_guard: "ReplayGuard") -> dict:
    """Build the routes to register on the existing pinned listener."""
    return {
        MACHINE_ENROLL_PATH: machine_enrollment_route(registry),
        MACHINE_AUTH_PATH: machine_authentication_route(registry, replay_guard),
    }
