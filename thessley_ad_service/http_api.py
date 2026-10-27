"""HTTP route factory for the first standalone AD service operation."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .machine_registry import MachineRegistry


MACHINE_ENROLL_PATH = "/thessley-ad/v1/machines/enroll"


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


def create_routes(registry: "MachineRegistry") -> dict:
    """Build the exact routes to register on the existing pinned listener."""
    return {MACHINE_ENROLL_PATH: machine_enrollment_route(registry)}
