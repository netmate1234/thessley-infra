"""HTTP route factory for the first standalone AD service operation."""

from __future__ import annotations

import re
from urllib.parse import urlencode
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .machine_registry import MachineRegistry
    from .machine_auth import ReplayGuard
    from .directory import ActiveDirectory
    from .challenges import ChallengeStore


MACHINE_ENROLL_PATH = "/thessley-ad/v1/machines/enroll"
MACHINE_AUTH_PATH = "/thessley-ad/v1/machines/authenticate"
PRINCIPAL_RESOLVE_PATH = "/thessley-ad/v1/principals/resolve"
LOGIN_START_PATH = "/thessley-ad/v1/requests"
PHONE_RESPONSE_PATH = "/thessley-ad/v1/requests/respond"
LOGIN_RESULT_PATH = "/thessley-ad/v1/requests/result"


def _authenticated_machine(machine_id: str, timestamp_text: str, nonce: str, signature: str,
                           path: str, raw_body: bytes, registry: "MachineRegistry",
                           replay_guard: "ReplayGuard") -> bool:
    from .machine_auth import verify_request

    try:
        timestamp = int(timestamp_text)
    except (TypeError, ValueError):
        return False
    public_key = registry.public_key(machine_id)
    return bool(public_key) and verify_request(
        public_key_spki_b64=public_key,
        signature_b64=signature,
        method="POST",
        path=path,
        machine_id=machine_id,
        timestamp=timestamp,
        nonce=nonce,
        body=raw_body,
        replay_guard=replay_guard,
    )


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

    def handle(_client_ip: str, body: dict, raw_body: bytes, auth_headers: dict[str, str]):
        expected = {
            "x-thessley-machine-id", "x-thessley-timestamp", "x-thessley-nonce", "x-thessley-signature"
        }
        if set(auth_headers) != expected or body != {}:
            return 400, {"result": "error", "message": "Invalid machine authentication request."}
        machine_id = auth_headers["x-thessley-machine-id"]
        if not _authenticated_machine(
            machine_id, auth_headers["x-thessley-timestamp"], auth_headers["x-thessley-nonce"],
            auth_headers["x-thessley-signature"], MACHINE_AUTH_PATH, raw_body, registry, replay_guard,
        ):
            return 401, {"result": "error", "message": "Machine authentication failed."}
        return 200, {"result": "authenticated", "machine_id": machine_id}

    return RawBodyRoute(handle)


def principal_resolve_route(registry: "MachineRegistry", replay_guard: "ReplayGuard",
                            directory: "ActiveDirectory", allowed_group_sids: frozenset[str]):
    """Resolve a signed SID request using AD as the sole group authority."""
    from thessley_pam.listener import RawBodyRoute

    from .directory import DirectoryUnavailable, PrincipalNotFound, validate_group_sid_allowlist

    allowed_group_sids = validate_group_sid_allowlist(allowed_group_sids)

    def handle(_client_ip: str, body: dict, raw_body: bytes, auth_headers: dict[str, str]):
        expected = {
            "x-thessley-machine-id", "x-thessley-timestamp", "x-thessley-nonce", "x-thessley-signature"
        }
        if set(auth_headers) != expected or set(body) != {"sid"} or not isinstance(body.get("sid"), str):
            return 400, {"result": "error", "message": "Invalid principal request."}
        machine_id = auth_headers["x-thessley-machine-id"]
        if not _authenticated_machine(
            machine_id, auth_headers["x-thessley-timestamp"], auth_headers["x-thessley-nonce"],
            auth_headers["x-thessley-signature"], PRINCIPAL_RESOLVE_PATH, raw_body, registry, replay_guard,
        ):
            return 401, {"result": "error", "message": "Machine authentication failed."}
        try:
            principal = directory.resolve_user_sid(body["sid"])
        except PrincipalNotFound:
            return 404, {"result": "error", "message": "Domain user was not found or is disabled."}
        except DirectoryUnavailable:
            return 503, {"result": "error", "message": "Domain authorization is temporarily unavailable."}
        authorized = bool(principal.group_sids.intersection(allowed_group_sids))
        return 200, {
            "result": "resolved",
            "principal": {
                "sid": principal.sid,
                "principal_id": principal.principal_id,
                "principal_type": "domain",
                "authority": principal.authority,
                "username": principal.username,
            },
            "authorized": authorized,
        }

    return RawBodyRoute(handle)


def login_start_route(registry: "MachineRegistry", replay_guard: "ReplayGuard",
                      directory: "ActiveDirectory", allowed_group_sids: frozenset[str],
                      challenges: "ChallengeStore", server_host: str, server_fingerprint: str):
    """Create a QR link only after the machine, SID, and AD group are verified."""
    from thessley_pam.listener import RawBodyRoute

    from .directory import DirectoryUnavailable, PrincipalNotFound
    from .directory import validate_group_sid_allowlist

    allowed_group_sids = validate_group_sid_allowlist(allowed_group_sids)
    if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", server_host):
        raise ValueError("Invalid AD service host")
    if not re.fullmatch(r"[a-f0-9]{64}", server_fingerprint):
        raise ValueError("Invalid AD service certificate fingerprint")

    def handle(_client_ip: str, body: dict, raw_body: bytes, auth_headers: dict[str, str]):
        expected = {
            "x-thessley-machine-id", "x-thessley-timestamp", "x-thessley-nonce", "x-thessley-signature"
        }
        if set(auth_headers) != expected or set(body) != {"sid", "context"}:
            return 400, {"result": "error", "message": "Invalid sign-in request."}
        if not isinstance(body.get("sid"), str) or body.get("context") not in ("interactive", "unlock"):
            return 400, {"result": "error", "message": "Invalid sign-in request."}
        machine_id = auth_headers["x-thessley-machine-id"]
        if not _authenticated_machine(
            machine_id, auth_headers["x-thessley-timestamp"], auth_headers["x-thessley-nonce"],
            auth_headers["x-thessley-signature"], LOGIN_START_PATH, raw_body, registry, replay_guard,
        ):
            return 401, {"result": "error", "message": "Machine authentication failed."}
        machine_name = registry.machine_name(machine_id)
        if not machine_name:
            return 401, {"result": "error", "message": "Machine authentication failed."}
        try:
            principal = directory.resolve_user_sid(body["sid"])
        except PrincipalNotFound:
            return 404, {"result": "error", "message": "Domain user was not found or is disabled."}
        except DirectoryUnavailable:
            return 503, {"result": "error", "message": "Domain authorization is temporarily unavailable."}
        if not principal.group_sids.intersection(allowed_group_sids):
            return 403, {"result": "error", "message": "This account is not authorized on this computer."}
        try:
            challenge = challenges.create(
                machine_id=machine_id,
                sid=principal.sid,
                username=principal.username,
                authority=principal.authority,
                context=body["context"],
            )
        except (RuntimeError, TypeError, ValueError):
            return 503, {"result": "error", "message": "Could not create a sign-in request."}
        link = "thessleypam://login?" + urlencode({
            "h": server_host,
            "p": "47810",
            "fp": server_fingerprint,
            "id": challenge["request_id"],
            "n": challenge["nonce"],
            "m": machine_id,
            "hn": machine_name,
            "u": principal.username,
            "pv": "2",
            "sid": principal.principal_id,
            "scope": "domain",
            "auth": principal.authority,
            "ctx": body["context"],
            "api": "ad",
        })
        return 201, {"result": "created", "request": challenge, "app_link": link}

    return RawBodyRoute(handle)


def phone_response_route(challenges: "ChallengeStore"):
    """Accept the signed Android v2 response; a request can transition once."""
    from thessley_pam.listener import RawBodyRoute

    def handle(_client_ip: str, body: dict, _raw_body: bytes, auth_headers: dict[str, str]):
        if auth_headers or set(body) != {"request_id", "credential_id", "action", "timestamp", "signature"}:
            return 400, {"result": "error", "message": "Invalid phone response."}
        timestamp = body.get("timestamp")
        if isinstance(timestamp, bool) or not isinstance(timestamp, int):
            return 400, {"result": "error", "message": "Invalid phone response."}
        accepted = challenges.respond(
            request_id=body.get("request_id"),
            credential_id=body.get("credential_id"),
            action=body.get("action"),
            timestamp=timestamp,
            signature_b64=body.get("signature"),
        )
        if not accepted:
            return 409, {"result": "error", "message": "The response was invalid, expired, or already used."}
        return 200, {"result": "ok"}

    return RawBodyRoute(handle)


def login_result_route(registry: "MachineRegistry", replay_guard: "ReplayGuard",
                       challenges: "ChallengeStore"):
    """Deliver one result only to the machine that created the request."""
    from thessley_pam.listener import RawBodyRoute

    def handle(_client_ip: str, body: dict, raw_body: bytes, auth_headers: dict[str, str]):
        expected = {
            "x-thessley-machine-id", "x-thessley-timestamp", "x-thessley-nonce", "x-thessley-signature"
        }
        if set(auth_headers) != expected or set(body) != {"request_id"} or not isinstance(body.get("request_id"), str):
            return 400, {"result": "error", "message": "Invalid result request."}
        machine_id = auth_headers["x-thessley-machine-id"]
        if not _authenticated_machine(
            machine_id, auth_headers["x-thessley-timestamp"], auth_headers["x-thessley-nonce"],
            auth_headers["x-thessley-signature"], LOGIN_RESULT_PATH, raw_body, registry, replay_guard,
        ):
            return 401, {"result": "error", "message": "Machine authentication failed."}
        result = challenges.consume_result(machine_id=machine_id, request_id=body["request_id"])
        if result is None:
            return 404, {"result": "error", "message": "Sign-in request was not found."}
        return 200, result

    return RawBodyRoute(handle)


def create_routes(registry: "MachineRegistry", replay_guard: "ReplayGuard",
                  directory: "ActiveDirectory", allowed_group_sids: frozenset[str],
                  challenges: "ChallengeStore", server_host: str, server_fingerprint: str) -> dict:
    """Build the routes to register on the existing pinned listener."""
    return {
        MACHINE_ENROLL_PATH: machine_enrollment_route(registry),
        MACHINE_AUTH_PATH: machine_authentication_route(registry, replay_guard),
        PRINCIPAL_RESOLVE_PATH: principal_resolve_route(registry, replay_guard, directory, allowed_group_sids),
        LOGIN_START_PATH: login_start_route(
            registry, replay_guard, directory, allowed_group_sids, challenges, server_host, server_fingerprint
        ),
        PHONE_RESPONSE_PATH: phone_response_route(challenges),
        LOGIN_RESULT_PATH: login_result_route(registry, replay_guard, challenges),
    }
