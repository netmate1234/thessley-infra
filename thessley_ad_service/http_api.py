"""HTTP route factory for the first standalone AD service operation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from collections.abc import Callable
from urllib.parse import urlencode
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .machine_registry import MachineRegistry
    from .machine_auth import ReplayGuard
    from .directory import ActiveDirectory
    from .challenges import ChallengeStore
    from .phone_registry import PhoneRegistry


MACHINE_ENROLL_PATH = "/thessley-ad/v1/machines/enroll"
MACHINE_AUTH_PATH = "/thessley-ad/v1/machines/authenticate"
DIRECTORY_USERS_PATH = "/thessley-ad/v1/directory/users"
PHONE_KEYS_PATH = "/thessley-ad/v1/directory/phone-keys"
PHONE_KEY_REVOKE_PATH = "/thessley-ad/v1/directory/phone-keys/revoke"
PRINCIPAL_RESOLVE_PATH = "/thessley-ad/v1/principals/resolve"
LOGIN_START_PATH = "/thessley-ad/v1/requests"
PHONE_RESPONSE_PATH = "/thessley-ad/v1/requests/respond"
LOGIN_RESULT_PATH = "/thessley-ad/v1/requests/result"
PHONE_ENROLL_START_PATH = "/thessley-ad/v1/enrollments"
PHONE_ENROLL_RESPONSE_PATH = "/thessley-ad/v1/enrollments/respond"
PHONE_ENROLL_STATUS_PATH = "/thessley-ad/v1/enrollments/status"
PHONE_ENROLL_CONFIRM_PATH = "/thessley-ad/v1/enrollments/confirm"
PHONE_ENROLL_CANCEL_PATH = "/thessley-ad/v1/enrollments/cancel"


@dataclass(frozen=True)
class RawBodyRoute:
    """Transport-neutral route that verifies signatures over exact HTTP bytes."""

    handler: Callable[[str, dict, bytes, dict[str, str]], tuple[int, dict]]
    response_wait: int = 15

    def __post_init__(self) -> None:
        if (isinstance(self.response_wait, bool) or not isinstance(self.response_wait, int)
                or not 1 <= self.response_wait <= 125):
            raise ValueError("Raw route response wait must be between 1 and 125 seconds.")


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


def directory_users_route(registry: "MachineRegistry", replay_guard: "ReplayGuard",
                          directory: "ActiveDirectory", allowed_group_sids: frozenset[str]):
    """Return a bounded directory view only to an enrolled, signed workstation."""
    from .directory import DirectoryUnavailable

    allowed_group_sids = frozenset(allowed_group_sids)

    def handle(_client_ip: str, body: dict, raw_body: bytes, auth_headers: dict[str, str]):
        expected = {
            "x-thessley-machine-id", "x-thessley-timestamp", "x-thessley-nonce", "x-thessley-signature"
        }
        if set(auth_headers) != expected or body != {}:
            return 400, {"result": "error", "message": "Invalid directory request."}
        machine_id = auth_headers["x-thessley-machine-id"]
        if not _authenticated_machine(
            machine_id, auth_headers["x-thessley-timestamp"], auth_headers["x-thessley-nonce"],
            auth_headers["x-thessley-signature"], DIRECTORY_USERS_PATH, raw_body, registry, replay_guard,
        ):
            return 401, {"result": "error", "message": "Machine authentication failed."}
        list_users = getattr(directory, "list_users", None)
        if not callable(list_users):
            return 503, {"result": "error", "message": "The AD directory listing is unavailable on this service."}
        try:
            snapshot = list_users(allowed_group_sids)
        except DirectoryUnavailable:
            return 503, {"result": "error", "message": "The AD directory is temporarily unavailable."}
        if (not isinstance(snapshot, dict) or not isinstance(snapshot.get("domain"), str)
                or not snapshot["domain"] or len(snapshot["domain"]) > 256
                or not isinstance(snapshot.get("users"), list) or len(snapshot["users"]) > 1000
                or not isinstance(snapshot.get("truncated"), bool)):
            return 503, {"result": "error", "message": "The AD directory returned an invalid response."}
        for user in snapshot["users"]:
            if (not isinstance(user, dict)
                    or not isinstance(user.get("sam"), str) or not user["sam"] or len(user["sam"]) > 64
                    or not isinstance(user.get("sid"), str) or not re.fullmatch(r"S-1-(?:[0-9]+-)+[0-9]+", user["sid"])
                    or not isinstance(user.get("name"), str) or len(user["name"]) > 256
                    or not isinstance(user.get("upn"), str) or len(user["upn"]) > 256
                    or not isinstance(user.get("enabled"), bool)
                    or not isinstance(user.get("authorized"), bool)):
                return 503, {"result": "error", "message": "The AD directory returned an invalid response."}
        return 200, {"result": "listed", **snapshot}

    return RawBodyRoute(handle)


def phone_keys_route(registry: "MachineRegistry", replay_guard: "ReplayGuard",
                     phones: "PhoneRegistry"):
    """List active phone-key metadata for the authenticated machine only."""
    def handle(_client_ip: str, body: dict, raw_body: bytes, auth_headers: dict[str, str]):
        expected = {"x-thessley-machine-id", "x-thessley-timestamp", "x-thessley-nonce", "x-thessley-signature"}
        if set(auth_headers) != expected or body != {}:
            return 400, {"result": "error", "message": "Invalid phone-key listing request."}
        machine_id = auth_headers["x-thessley-machine-id"]
        if not _authenticated_machine(machine_id, auth_headers["x-thessley-timestamp"],
                                      auth_headers["x-thessley-nonce"], auth_headers["x-thessley-signature"],
                                      PHONE_KEYS_PATH, raw_body, registry, replay_guard):
            return 401, {"result": "error", "message": "Machine authentication failed."}
        if not registry.machine_name(machine_id):
            return 401, {"result": "error", "message": "Machine authentication failed."}
        keys = phones.list_for_machine(machine_id)
        if len(keys) > 5000:
            return 503, {"result": "error", "message": "The phone-key listing is too large."}
        return 200, {"result": "listed", "keys": keys}
    return RawBodyRoute(handle)


def phone_key_revoke_route(registry: "MachineRegistry", replay_guard: "ReplayGuard",
                           phones: "PhoneRegistry"):
    """Revoke a key only when it belongs to the authenticated machine."""
    def handle(_client_ip: str, body: dict, raw_body: bytes, auth_headers: dict[str, str]):
        expected = {"x-thessley-machine-id", "x-thessley-timestamp", "x-thessley-nonce", "x-thessley-signature"}
        credential_id = body.get("credential_id")
        if (set(auth_headers) != expected or set(body) != {"credential_id"}
                or not isinstance(credential_id, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{32,64}", credential_id)):
            return 400, {"result": "error", "message": "Invalid phone-key revocation request."}
        machine_id = auth_headers["x-thessley-machine-id"]
        if not _authenticated_machine(machine_id, auth_headers["x-thessley-timestamp"],
                                      auth_headers["x-thessley-nonce"], auth_headers["x-thessley-signature"],
                                      PHONE_KEY_REVOKE_PATH, raw_body, registry, replay_guard):
            return 401, {"result": "error", "message": "Machine authentication failed."}
        if not registry.machine_name(machine_id):
            return 401, {"result": "error", "message": "Machine authentication failed."}
        if not phones.revoke_for_machine(credential_id, machine_id):
            return 404, {"result": "error", "message": "No active matching phone key was found for this computer."}
        return 200, {"result": "revoked"}
    return RawBodyRoute(handle)


def principal_resolve_route(registry: "MachineRegistry", replay_guard: "ReplayGuard",
                            directory: "ActiveDirectory", allowed_group_sids: frozenset[str], login_policy=None):
    """Resolve a signed SID request using AD as the sole group authority."""
    from .directory import DirectoryUnavailable, PrincipalNotFound, validate_group_sid_allowlist
    from .login_policy import PolicyError, METHOD_TPM

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
        try:
            policy = login_policy.resolve(machine_id, principal.group_sids) if login_policy else {
                "method": METHOD_TPM, "source": "domain-default"
            }
        except PolicyError:
            return 503, {"result": "error", "message": "The workstation sign-in policy is unavailable."}
        return 200, {
            "result": "resolved",
            "credential_method": policy["method"],
            "policy_source": policy["source"],
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
                      challenges: "ChallengeStore", server_host: str,
                      server_fingerprint: str | Callable[[], str], login_policy=None,
                      certificate_template: str | None = None):
    """Create a QR link only after the machine, SID, and AD group are verified."""
    from .directory import DirectoryUnavailable, PrincipalNotFound
    from .directory import validate_group_sid_allowlist
    from .login_policy import METHOD_EPHEMERAL_CERT, METHOD_TPM, METHOD_WINDOWS, PolicyError
    from .protocol import validate_certificate_template

    allowed_group_sids = validate_group_sid_allowlist(allowed_group_sids)
    try:
        certificate_template = validate_certificate_template(certificate_template)
    except ValueError as exc:
        raise ValueError("Invalid configured AD CS certificate template") from exc
    if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", server_host):
        raise ValueError("Invalid AD service host")
    fingerprint_provider = server_fingerprint if callable(server_fingerprint) else lambda: server_fingerprint

    def handle(_client_ip: str, body: dict, raw_body: bytes, auth_headers: dict[str, str]):
        expected = {
            "x-thessley-machine-id", "x-thessley-timestamp", "x-thessley-nonce", "x-thessley-signature"
        }
        body_fields = set(body)
        if (set(auth_headers) != expected or body_fields not in (
                {"sid", "context"}, {"sid", "context", "certificate_request_sha256"})):
            return 400, {"result": "error", "message": "Invalid sign-in request."}
        if not isinstance(body.get("sid"), str) or body.get("context") not in ("interactive", "unlock", "ssh"):
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
        fingerprint = fingerprint_provider()
        if not isinstance(fingerprint, str) or not re.fullmatch(r"[a-f0-9]{64}", fingerprint):
            return 503, {"result": "error", "message": "The approval certificate is not ready."}
        try:
            principal = directory.resolve_user_sid(body["sid"])
        except PrincipalNotFound:
            return 404, {"result": "error", "message": "Domain user was not found or is disabled."}
        except DirectoryUnavailable:
            return 503, {"result": "error", "message": "Domain authorization is temporarily unavailable."}
        if not principal.group_sids.intersection(allowed_group_sids):
            return 403, {"result": "error", "message": "This account is not authorized on this computer."}
        try:
            policy = login_policy.resolve(machine_id, principal.group_sids) if login_policy else {
                "method": METHOD_TPM, "source": "domain-default"
            }
        except PolicyError:
            return 503, {"result": "error", "message": "The workstation sign-in policy is unavailable."}
        if policy["method"] == METHOD_WINDOWS:
            return 403, {"result": "disabled", "message": "Thessley phone sign-in is disabled for this account on this workstation."}
        certificate_pilot = policy["method"] == METHOD_EPHEMERAL_CERT
        if certificate_pilot:
            if certificate_template is None:
                return 503, {"result": "unsupported", "message": "The certificate sign-in template is not configured."}
            digest = body.get("certificate_request_sha256")
            if (body["context"] != "interactive" or not isinstance(digest, str)
                    or not re.fullmatch(r"[a-f0-9]{64}", digest)):
                return 400, {"result": "error", "message": "The certificate sign-in request is invalid."}
        elif "certificate_request_sha256" in body:
            return 400, {"result": "error", "message": "This sign-in method does not accept a certificate request."}
        elif policy["method"] != METHOD_TPM:
            return 503, {"result": "unsupported", "message": "The selected Thessley sign-in method is not available yet."}
        try:
            challenge_args = dict(
                machine_id=machine_id,
                sid=principal.sid,
                username=principal.username,
                authority=principal.authority,
                context=body["context"],
                # Give a person enough time to unlock the phone, scan, and
                # approve. The challenge remains one-use and machine-bound.
                lifetime_seconds=180,
            )
            if certificate_pilot:
                challenge_args.update({
                    "certificate_request_sha256": body["certificate_request_sha256"],
                    "certificate_template": certificate_template,
                })
            challenge = challenges.create(**challenge_args)
        except (RuntimeError, TypeError, ValueError):
            return 503, {"result": "error", "message": "Could not create a sign-in request."}
        link_values = {
            "h": server_host,
            "p": "47810",
            "fp": fingerprint,
            "id": challenge["request_id"],
            "n": challenge["nonce"],
            "m": machine_id,
            "hn": machine_name,
            "u": principal.username,
            "pv": "3" if certificate_pilot else "2",
            "sid": principal.principal_id,
            "scope": "domain",
            "auth": principal.authority,
            "ctx": body["context"],
            "api": "ad",
        }
        if certificate_pilot:
            link_values.update({
                "csr": challenge["certificate_request_sha256"],
                "tmpl": challenge["certificate_template"],
                "exp": str(int(challenge["expires_at"])),
            })
        link = "thessleypam://login?" + urlencode(link_values)
        return 201, {"result": "created", "credential_method": policy["method"],
                     "policy_source": policy["source"], "request": challenge, "app_link": link}

    return RawBodyRoute(handle)


def phone_response_route(challenges: "ChallengeStore"):
    """Accept one signed approval or a nonce-bound refusal from Android."""
    def handle(_client_ip: str, body: dict, _raw_body: bytes, auth_headers: dict[str, str]):
        if auth_headers or set(body) != {"request_id", "credential_id", "action", "timestamp", "signature", "nonce"}:
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
            nonce=body.get("nonce"),
        )
        if not accepted:
            return 409, {"result": "error", "message": "The response was invalid, expired, or already used."}
        return 200, {"result": "ok"}

    return RawBodyRoute(handle)


def login_result_route(registry: "MachineRegistry", replay_guard: "ReplayGuard",
                       challenges: "ChallengeStore"):
    """Deliver one result only to the machine that created the request."""
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


def phone_enrollment_start_route(registry: "MachineRegistry", replay_guard: "ReplayGuard",
                                 directory: "ActiveDirectory", allowed_group_sids: frozenset[str],
                                 phones: "PhoneRegistry", server_host: str,
                                 server_fingerprint: str | Callable[[], str]):
    """Start first-phone enrollment for an AD-authorized domain SID."""
    from .directory import DirectoryUnavailable, PrincipalNotFound, validate_group_sid_allowlist

    allowed_group_sids = validate_group_sid_allowlist(allowed_group_sids)
    if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", server_host):
        raise ValueError("Invalid AD service host")
    fingerprint_provider = server_fingerprint if callable(server_fingerprint) else lambda: server_fingerprint

    def handle(_client_ip: str, body: dict, raw_body: bytes, auth_headers: dict[str, str]):
        expected = {
            "x-thessley-machine-id", "x-thessley-timestamp", "x-thessley-nonce", "x-thessley-signature"
        }
        if set(auth_headers) != expected or set(body) != {"sid"} or not isinstance(body.get("sid"), str):
            return 400, {"result": "error", "message": "Invalid phone enrollment request."}
        machine_id = auth_headers["x-thessley-machine-id"]
        if not _authenticated_machine(
            machine_id, auth_headers["x-thessley-timestamp"], auth_headers["x-thessley-nonce"],
            auth_headers["x-thessley-signature"], PHONE_ENROLL_START_PATH, raw_body, registry, replay_guard,
        ):
            return 401, {"result": "error", "message": "Machine authentication failed."}
        machine_name = registry.machine_name(machine_id)
        fingerprint = fingerprint_provider()
        if not machine_name or not isinstance(fingerprint, str) or not re.fullmatch(r"[a-f0-9]{64}", fingerprint):
            return 503, {"result": "error", "message": "The AD service is not ready for enrollment."}
        try:
            principal = directory.resolve_user_sid(body["sid"])
        except PrincipalNotFound:
            return 404, {"result": "error", "message": "Domain user was not found or is disabled."}
        except DirectoryUnavailable:
            return 503, {"result": "error", "message": "Domain authorization is temporarily unavailable."}
        if not principal.group_sids.intersection(allowed_group_sids):
            return 403, {"result": "error", "message": "This account is not authorized to enroll a phone."}
        enrollment = phones.create_enrollment(
            machine_id=machine_id, sid=principal.sid, username=principal.username, authority=principal.authority,
        )
        if enrollment is None:
            return 503, {"result": "error", "message": "Could not create a phone enrollment request."}
        link = "thessleypam://enroll?" + urlencode({
            "h": server_host, "p": "47810", "fp": fingerprint, "id": enrollment["request_id"],
            "n": enrollment["nonce"], "m": machine_id, "hn": machine_name, "u": principal.username,
            "pv": "2", "sid": enrollment["principal_id"], "scope": "domain",
            "auth": principal.authority, "ctx": "enrollment", "api": "ad",
        })
        return 201, {"result": "created", "request": enrollment, "app_link": link}

    return RawBodyRoute(handle)


def phone_enrollment_response_route(phones: "PhoneRegistry"):
    """Verify the new Android key and wait for its pairing code to be confirmed on Windows."""
    def handle(_client_ip: str, body: dict, _raw_body: bytes, auth_headers: dict[str, str]):
        expected = {"request_id", "public_key", "algorithm", "label", "timestamp", "proof_signature", "attestation_chain"}
        if (auth_headers or set(body) != expected
                or not isinstance(body.get("request_id"), str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", body["request_id"])):
            return 400, {"result": "error", "message": "Invalid phone enrollment response."}
        chain = body.get("attestation_chain")
        if (body.get("algorithm") != "ES256" or not isinstance(chain, list) or len(chain) > 10
                or any(not isinstance(cert, str) or len(cert) > 16384 for cert in chain)):
            return 400, {"result": "error", "message": "Invalid phone enrollment response."}
        timestamp = body.get("timestamp")
        if isinstance(timestamp, bool) or not isinstance(timestamp, int):
            return 400, {"result": "error", "message": "Invalid phone enrollment response."}
        if not phones.submit_enrollment(
            request_id=body.get("request_id"), public_key_spki_b64=body.get("public_key"),
            label=body.get("label"), timestamp=timestamp, signature_b64=body.get("proof_signature"),
        ):
            return 409, {"result": "error", "message": "Phone proof was invalid, expired, or already used."}
        result = phones.wait_enrollment(body["request_id"], timeout=110)
        if result and result.get("status") == "denied":
            return 403, {"result": "denied", "message": "Phone enrollment was cancelled on the Windows computer."}
        if not result or result.get("status") != "confirmed":
            return 409, {"result": "error", "message": "Pairing was not confirmed on the Windows computer."}
        return 200, {"result": "ok", "credential_id": result["credential_id"],
                     "username": result["username"]}

    return RawBodyRoute(handle, response_wait=115)


def phone_enrollment_status_route(registry: "MachineRegistry", replay_guard: "ReplayGuard",
                                  phones: "PhoneRegistry"):
    """Expose only the pairing state to the machine that began that enrollment."""
    def handle(_client_ip: str, body: dict, raw_body: bytes, auth_headers: dict[str, str]):
        expected = {
            "x-thessley-machine-id", "x-thessley-timestamp", "x-thessley-nonce", "x-thessley-signature"
        }
        if (set(auth_headers) != expected or set(body) != {"request_id"}
                or not isinstance(body.get("request_id"), str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", body["request_id"])):
            return 400, {"result": "error", "message": "Invalid enrollment status request."}
        machine_id = auth_headers["x-thessley-machine-id"]
        if not _authenticated_machine(
            machine_id, auth_headers["x-thessley-timestamp"], auth_headers["x-thessley-nonce"],
            auth_headers["x-thessley-signature"], PHONE_ENROLL_STATUS_PATH, raw_body, registry, replay_guard,
        ):
            return 401, {"result": "error", "message": "Machine authentication failed."}
        state = phones.enrollment_status(machine_id=machine_id, request_id=body["request_id"])
        if state is None:
            return 404, {"result": "error", "message": "Phone enrollment was not found."}
        return 200, state

    return RawBodyRoute(handle)


def phone_enrollment_confirm_route(registry: "MachineRegistry", replay_guard: "ReplayGuard",
                                   phones: "PhoneRegistry"):
    """Activate a staged phone key only after the Windows screen's pairing code matches."""
    def handle(_client_ip: str, body: dict, raw_body: bytes, auth_headers: dict[str, str]):
        expected = {
            "x-thessley-machine-id", "x-thessley-timestamp", "x-thessley-nonce", "x-thessley-signature"
        }
        if (set(auth_headers) != expected or set(body) != {"request_id", "pairing_code"}
                or not isinstance(body.get("request_id"), str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", body["request_id"])):
            return 400, {"result": "error", "message": "Invalid enrollment confirmation."}
        machine_id = auth_headers["x-thessley-machine-id"]
        if not _authenticated_machine(
            machine_id, auth_headers["x-thessley-timestamp"], auth_headers["x-thessley-nonce"],
            auth_headers["x-thessley-signature"], PHONE_ENROLL_CONFIRM_PATH, raw_body, registry, replay_guard,
        ):
            return 401, {"result": "error", "message": "Machine authentication failed."}
        if not phones.confirm_enrollment(
            machine_id=machine_id, request_id=body.get("request_id"), pairing_code=body.get("pairing_code"),
        ):
            return 409, {"result": "error", "message": "The pairing code did not match or the request expired."}
        return 200, {"result": "confirmed"}

    return RawBodyRoute(handle)


def phone_enrollment_cancel_route(registry: "MachineRegistry", replay_guard: "ReplayGuard",
                                  phones: "PhoneRegistry"):
    """Cancel a pending enrollment from its originating authenticated machine."""
    def handle(_client_ip: str, body: dict, raw_body: bytes, auth_headers: dict[str, str]):
        expected = {
            "x-thessley-machine-id", "x-thessley-timestamp", "x-thessley-nonce", "x-thessley-signature"
        }
        if (set(auth_headers) != expected or set(body) != {"request_id"}
                or not isinstance(body.get("request_id"), str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", body["request_id"])):
            return 400, {"result": "error", "message": "Invalid enrollment cancellation."}
        machine_id = auth_headers["x-thessley-machine-id"]
        if not _authenticated_machine(
            machine_id, auth_headers["x-thessley-timestamp"], auth_headers["x-thessley-nonce"],
            auth_headers["x-thessley-signature"], PHONE_ENROLL_CANCEL_PATH, raw_body, registry, replay_guard,
        ):
            return 401, {"result": "error", "message": "Machine authentication failed."}
        if not phones.cancel_enrollment(machine_id=machine_id, request_id=body["request_id"]):
            return 409, {"result": "error", "message": "Phone enrollment is no longer pending."}
        return 200, {"result": "cancelled"}

    return RawBodyRoute(handle)


def create_routes(registry: "MachineRegistry", replay_guard: "ReplayGuard",
                  directory: "ActiveDirectory", allowed_group_sids: frozenset[str],
                  challenges: "ChallengeStore", server_host: str,
                  server_fingerprint: str | Callable[[], str], phones: "PhoneRegistry",
                  login_policy=None, certificate_template: str | None = None) -> dict:
    """Build routes without binding them to a particular HTTPS listener."""
    return {
        MACHINE_ENROLL_PATH: machine_enrollment_route(registry),
        MACHINE_AUTH_PATH: machine_authentication_route(registry, replay_guard),
        DIRECTORY_USERS_PATH: directory_users_route(registry, replay_guard, directory, allowed_group_sids),
        PHONE_KEYS_PATH: phone_keys_route(registry, replay_guard, phones),
        PHONE_KEY_REVOKE_PATH: phone_key_revoke_route(registry, replay_guard, phones),
        PRINCIPAL_RESOLVE_PATH: principal_resolve_route(
            registry, replay_guard, directory, allowed_group_sids, login_policy
        ),
        LOGIN_START_PATH: login_start_route(
            registry, replay_guard, directory, allowed_group_sids, challenges, server_host, server_fingerprint,
            login_policy, certificate_template,
        ),
        PHONE_RESPONSE_PATH: phone_response_route(challenges),
        LOGIN_RESULT_PATH: login_result_route(registry, replay_guard, challenges),
        PHONE_ENROLL_START_PATH: phone_enrollment_start_route(
            registry, replay_guard, directory, allowed_group_sids, phones, server_host, server_fingerprint
        ),
        PHONE_ENROLL_RESPONSE_PATH: phone_enrollment_response_route(phones),
        PHONE_ENROLL_STATUS_PATH: phone_enrollment_status_route(registry, replay_guard, phones),
        PHONE_ENROLL_CONFIRM_PATH: phone_enrollment_confirm_route(registry, replay_guard, phones),
        PHONE_ENROLL_CANCEL_PATH: phone_enrollment_cancel_route(registry, replay_guard, phones),
    }
