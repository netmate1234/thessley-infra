<?php

namespace Drupal\thessley_passkey;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Database\Connection;

/**
 * Database access for Passkey Login: enrolled phones (long-lived) and the
 * short-lived login / enroll handshake rows.
 *
 * Every query goes through Drupal's database API with placeholders; nothing
 * request-supplied is ever concatenated into SQL.
 */
class PasskeyStore {

  public function __construct(
    protected Connection $db,
    protected TimeInterface $time,
  ) {}

  /**
   * 32 random bytes, base64url, no padding (43 characters).
   *
   * Matches the request_id / nonce / credential_id lengths the Android app
   * and the column widths assume.
   */
  public function randomToken(): string {
    return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
  }

  // ---- Requests (login / enroll / 2fa handshakes) ----------------------

  /**
   * Creates a pending request.
   *
   * @param string $type
   *   'login', 'enroll' or '2fa'.
   * @param int|null $requester_uid
   *   NULL for an anonymous login (whichever device approves it identifies
   *   the user); an account id when the request is bound to an account (2fa,
   *   enroll, or a login started with the username prompt). 0 is the
   *   placeholder for a username that does not exist: no device belongs to
   *   account 0, so such a request can never be approved.
   *
   * @return array{request_id:string, nonce:string, ip:string, expires_in:int}
   */
  public function createRequest(string $type, ?int $requester_uid, int $ttl, string $ip): array {
    $request_id = $this->randomToken();
    $nonce = $this->randomToken();
    $now = $this->time->getRequestTime();

    $this->db->insert('thessley_passkey_requests')
      ->fields([
        'request_id' => $request_id,
        'type' => $type,
        'nonce' => $nonce,
        'status' => 'pending',
        'requester_uid' => $requester_uid,
        'ip' => substr($ip, 0, 45),
        'created' => $now,
        'expires' => $now + $ttl,
      ])
      ->execute();

    return [
      'request_id' => $request_id,
      'nonce' => $nonce,
      'ip' => $ip,
      'expires_in' => $ttl,
    ];
  }

  public function getRequest(string $request_id): ?object {
    $row = $this->db->query(
      'SELECT * FROM {thessley_passkey_requests} WHERE request_id = :id',
      [':id' => $request_id]
    )->fetchObject();
    return $row ?: NULL;
  }

  public function isExpired(object $request): bool {
    return (int) $request->expires < $this->time->getRequestTime();
  }

  /**
   * Resolves a pending, unexpired request; FALSE if it already was resolved.
   *
   * One atomic UPDATE (pending -> $status), so two simultaneous responses can
   * never both win. This is what makes a request single-use.
   */
  public function resolveRequest(string $request_id, string $status, ?int $approver_uid = NULL, ?int $credential_row = NULL): bool {
    $fields = [
      'status' => $status,
      'approved' => $this->time->getRequestTime(),
    ];
    if ($approver_uid !== NULL) {
      $fields['approver_uid'] = $approver_uid;
    }
    if ($credential_row !== NULL) {
      $fields['credential_row'] = $credential_row;
    }

    $updated = $this->db->update('thessley_passkey_requests')
      ->fields($fields)
      ->condition('request_id', $request_id)
      ->condition('status', 'pending')
      ->condition('expires', $this->time->getRequestTime(), '>=')
      ->execute();

    return (bool) $updated;
  }

  /** Records which device an approved enrol request created. */
  public function attachDevice(string $request_id, int $row_id): void {
    $this->db->update('thessley_passkey_requests')
      ->fields(['credential_row' => $row_id])
      ->condition('request_id', $request_id)
      ->execute();
  }

  /**
   * Marks an approved request consumed, once.
   *
   * Returns TRUE only for the caller that actually flipped it, so a captured
   * or replayed status response can never complete a login a second time.
   */
  public function consumeRequest(string $request_id): bool {
    return (bool) $this->db->update('thessley_passkey_requests')
      ->fields(['status' => 'consumed'])
      ->condition('request_id', $request_id)
      ->condition('status', 'approved')
      ->execute();
  }

  public function pruneExpiredRequests(): void {
    $now = $this->time->getRequestTime();
    $this->db->delete('thessley_passkey_requests')
      ->condition($this->db->condition('OR')
        ->condition('expires', $now, '<')
        ->condition($this->db->condition('AND')
          ->condition('status', 'pending', '<>')
          ->condition('created', $now - 86400, '<')))
      ->execute();
  }

  // ---- Passkeys (enrolled devices) --------------------------------------

  public function addPasskey(int $uid, string $public_key, string $algorithm, string $label): string {
    $credential_id = $this->randomToken();

    $this->db->insert('thessley_passkeys')
      ->fields([
        'uid' => $uid,
        'credential_id' => $credential_id,
        'public_key' => $public_key,
        'algorithm' => $algorithm !== '' ? substr($algorithm, 0, 16) : 'ES256',
        'counter' => 0,
        'label' => substr($label, 0, 100),
        'created' => $this->time->getRequestTime(),
      ])
      ->execute();

    return $credential_id;
  }

  /**
   * One of 'software' | 'tee' | 'strongbox', or NULL when the device sent no
   * attestation chain or it could not be parsed (distinct from a confirmed
   * 'software' result).
   */
  public function setAttestationLevel(int $row_id, ?string $level): void {
    $this->db->update('thessley_passkeys')
      ->fields(['attestation_level' => $level])
      ->condition('id', $row_id)
      ->execute();
  }

  /** An active (not revoked) device by its credential id. */
  public function getPasskeyByCredential(string $credential_id): ?object {
    $row = $this->db->query(
      'SELECT * FROM {thessley_passkeys} WHERE credential_id = :c AND revoked IS NULL',
      [':c' => $credential_id]
    )->fetchObject();
    return $row ?: NULL;
  }

  public function getRowId(string $credential_id): int {
    return (int) $this->db->query(
      'SELECT id FROM {thessley_passkeys} WHERE credential_id = :c',
      [':c' => $credential_id]
    )->fetchField();
  }

  public function getCredentialForRow(int $row_id): ?string {
    $value = $this->db->query(
      'SELECT credential_id FROM {thessley_passkeys} WHERE id = :id',
      [':id' => $row_id]
    )->fetchField();
    return $value !== FALSE ? (string) $value : NULL;
  }

  /**
   * A user's devices, most recently used first; devices never used come last,
   * newest first.
   *
   * @return object[]
   */
  public function devicesForUser(int $uid): array {
    return $this->db->query(
      'SELECT id, credential_id, label, attestation_level, created, last_used, revoked FROM {thessley_passkeys} WHERE uid = :uid ORDER BY (last_used IS NULL), last_used DESC, created DESC, id DESC',
      [':uid' => $uid]
    )->fetchAll();
  }

  public function hasActiveDevice(int $uid): bool {
    return (bool) $this->db->query(
      'SELECT 1 FROM {thessley_passkeys} WHERE uid = :uid AND revoked IS NULL',
      [':uid' => $uid]
    )->fetchField();
  }

  public function getDevice(int $id): ?object {
    $row = $this->db->query('SELECT * FROM {thessley_passkeys} WHERE id = :id', [':id' => $id])->fetchObject();
    return $row ?: NULL;
  }

  public function bumpCounterAndTouch(int $id, int $new_counter): void {
    $this->db->update('thessley_passkeys')
      ->fields(['counter' => $new_counter, 'last_used' => $this->time->getRequestTime()])
      ->condition('id', $id)
      ->execute();
  }

  /**
   * Revokes a device. Scoped to its owner so a guessed or incremented id can
   * never revoke someone else's phone.
   */
  public function revoke(int $id, int $uid): bool {
    return (bool) $this->db->update('thessley_passkeys')
      ->fields(['revoked' => $this->time->getRequestTime()])
      ->condition('id', $id)
      ->condition('uid', $uid)
      ->isNull('revoked')
      ->execute();
  }

  /** Removes everything about an account (called when the account is deleted). */
  public function deleteForUser(int $uid): void {
    $this->db->delete('thessley_passkeys')->condition('uid', $uid)->execute();
    $this->db->delete('thessley_passkey_requests')
      ->condition($this->db->condition('OR')
        ->condition('requester_uid', $uid)
        ->condition('approver_uid', $uid))
      ->execute();
  }

}
