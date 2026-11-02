<?php

namespace Drupal\thessley_passkey\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Url;
use Drupal\thessley_passkey\Crypto;
use Drupal\thessley_passkey\PasskeyManager;
use Drupal\user\UserInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * The JSON endpoints the Thessley Passkey Android app and the login page
 * speak. Same paths, request fields, response fields, error codes and HTTP
 * statuses as the WordPress plugin's thessley/v1/passkey routes, so one app
 * works against both.
 */
class ApiController extends ControllerBase {

  public function __construct(protected PasskeyManager $manager) {}

  public static function create(ContainerInterface $container) {
    return new static($container->get('thessley_passkey.manager'));
  }

  // ---- helpers -------------------------------------------------------------

  protected function json(array $data, int $status = 200): JsonResponse {
    $response = new JsonResponse($data, $status);
    $response->headers->set('Cache-Control', 'no-store, private');
    return $response;
  }

  /** Error body in the shape the app already parses: {code, message, data:{status}}. */
  protected function error(string $code, string $message, int $status): JsonResponse {
    return $this->json(['code' => $code, 'message' => $message, 'data' => ['status' => $status]], $status);
  }

  /** A body field: JSON body first, then form-encoded, then query string. */
  protected function param(Request $request, string $name): mixed {
    static $cache = [];
    $key = spl_object_id($request);
    if (!isset($cache[$key])) {
      $decoded = json_decode((string) $request->getContent(), TRUE);
      $cache[$key] = is_array($decoded) ? $decoded : [];
    }
    return $cache[$key][$name] ?? $request->request->all()[$name] ?? $request->query->all()[$name] ?? NULL;
  }

  protected function expired(object $row): bool {
    return $this->manager->store()->isExpired($row);
  }

  protected function loadUser(int $uid): ?UserInterface {
    $account = $this->entityTypeManager()->getStorage('user')->load($uid);
    return $account instanceof UserInterface ? $account : NULL;
  }

  // ---- login (and 2fa) -----------------------------------------------------

  public function loginStart(Request $request): JsonResponse {
    $m = $this->manager;
    if ($m->rateLimited('login_start')) {
      return $this->error('thessley_rate_limited', 'Too many requests.', 429);
    }

    // Anonymous by default: whichever enrolled device approves IS the
    // identification. With the username prompt on, the request is created for
    // the typed account instead.
    $requester = NULL;
    $typed = '';

    if ($m->identify()) {
      $raw = $this->param($request, 'username');
      $typed = is_string($raw) ? mb_substr(trim(preg_replace('/[\x00-\x1F\x7F]+/u', '', $raw)), 0, 100) : '';
      if ($typed === '') {
        return $this->error('thessley_bad_request', 'Enter your username.', 400);
      }

      $user = user_load_by_name($typed) ?: (filter_var($typed, FILTER_VALIDATE_EMAIL) ? user_load_by_mail($typed) : FALSE);

      // An unknown name gets a real, working-looking request bound to account
      // 0, which no device can ever match, so nothing reveals which usernames
      // exist or have a device. The typed text (not the canonical name) goes
      // into the link for the same reason: echoing it would turn an email
      // address into its username.
      $requester = $user ? (int) $user->id() : 0;
    }

    $result = $m->store()->createRequest('login', $requester, PasskeyManager::LOGIN_TTL, $m->clientIp());
    $result['url'] = $m->authUrl('login', $result['request_id']);
    $result['app_link'] = $m->appLink('login', $result['request_id'], $result['nonce'], $result['ip'], $typed);

    $response = $this->json($result);
    $response->headers->setCookie($m->bindBrowser($result['request_id']));
    return $response;
  }

  public function loginStatus(Request $request, string $id): JsonResponse {
    $m = $this->manager;
    $store = $m->store();
    $row = $store->getRequest($id);

    if (!$row || !in_array($row->type, ['login', '2fa'], TRUE)) {
      return $this->json(['status' => 'expired']);
    }
    if ($this->expired($row) && $row->status === 'pending') {
      return $this->json(['status' => 'expired']);
    }

    if ($row->status === 'approved') {
      // Only the browser that started this request may receive the session;
      // anyone else polling the same id just sees "pending". Not consumed
      // here, so the real browser can still complete on its next poll.
      if (!$m->browserMatches($id, $request)) {
        $m->audit('login_csrf_blocked', 'request ' . $id . ' polled by a browser that never started it', TRUE);
        return $this->json(['status' => 'pending']);
      }

      $account = $this->loadUser((int) $row->approver_uid);
      if (!$account || !$account->isActive()) {
        $store->consumeRequest($id);
        $m->forgetBinding($id);
        return $this->json(['status' => 'denied']);
      }

      // Single use: only the caller that flips approved -> consumed gets the
      // session, so a replayed copy of this response cannot log in twice.
      if (!$store->consumeRequest($id)) {
        return $this->json(['status' => 'expired']);
      }
      $m->forgetBinding($id);

      user_login_finalize($account);
      $m->audit('login_approved', 'user #' . $account->id());

      return $this->json([
        'status' => 'approved',
        'redirect_to' => Url::fromRoute('entity.user.canonical', ['user' => $account->id()])->toString(),
      ]);
    }

    if ($row->status === 'consumed') {
      return $this->json(['status' => 'expired']);
    }

    return $this->json(['status' => $row->status]);
  }

  public function loginRespond(Request $request, string $id): JsonResponse {
    $m = $this->manager;
    $store = $m->store();

    $cred_id = (string) $this->param($request, 'credential_id');
    $action = (string) $this->param($request, 'action');
    $timestamp = (int) $this->param($request, 'timestamp');
    $signature = (string) $this->param($request, 'signature');

    if (!in_array($action, ['approve', 'deny'], TRUE)) {
      return $this->error('thessley_bad_request', 'Invalid action.', 400);
    }

    $row = $store->getRequest($id);
    if (!$row || !in_array($row->type, ['login', '2fa'], TRUE) || $row->status !== 'pending' || $this->expired($row)) {
      return $this->error('thessley_expired', 'This request is no longer valid.', 409);
    }
    if (!Crypto::timestamp_fresh($timestamp)) {
      return $this->error('thessley_stale', 'Timestamp out of range.', 401);
    }

    $passkey = $store->getPasskeyByCredential($cred_id);
    $account = $passkey ? $this->loadUser((int) $passkey->uid) : NULL;
    if (!$passkey || !$account || !$account->isActive() || !$account->hasPermission('use thessley passkey')) {
      return $this->error('thessley_unknown_device', 'Unknown or revoked device.', 401);
    }

    // A request that already knows who is logging in (2fa, or a login started
    // with the username prompt) may only be resolved by that account's own
    // devices. Requester 0 = a username that does not exist: no device
    // belongs to it, so it can never resolve. Only an anonymous login has
    // NULL here.
    if ($row->requester_uid !== NULL && (int) $row->requester_uid !== (int) $passkey->uid) {
      $m->audit('signature_invalid', 'credential ' . $cred_id . " tried to resolve another account's " . $row->type . ' request', TRUE);
      return $this->error('thessley_wrong_account', 'This device belongs to a different account.', 403);
    }

    // The real enforcement boundary for the 2fa-bypass: an anonymous 'login'
    // approval is a single factor, so it can never finish a login for an
    // account whose effective mode is '2fa'. Hiding the QR in the UI only
    // stops clicking; this stops anyone calling the endpoint directly.
    if ($row->type === 'login' && $action === 'approve' && $m->effectiveModeForUser((int) $passkey->uid) === '2fa') {
      $m->audit('anonymous_login_blocked', 'credential ' . $cred_id . ' - account requires password first', TRUE);
      return $this->error('thessley_2fa_required', 'This account requires your password first — log in with it, then confirm with the Thessley Passkey app.', 403);
    }

    $message = Crypto::canonical_string($row->type, $id, $m->origin(), $row->nonce, $timestamp, $action);
    if (!Crypto::verify($passkey->public_key, $message, $signature)) {
      $m->audit('signature_invalid', 'credential ' . $cred_id, TRUE);
      return $this->error('thessley_bad_signature', 'Signature verification failed.', 401);
    }

    $store->bumpCounterAndTouch((int) $passkey->id, (int) $passkey->counter + 1);

    if ($action === 'deny') {
      $store->resolveRequest($id, 'denied', (int) $passkey->uid, (int) $passkey->id);
      $m->audit('login_denied', 'user #' . $passkey->uid . ' denied a login attempt not initiated by them');
      return $this->json(['result' => 'ok']);
    }

    if (!$store->resolveRequest($id, 'approved', (int) $passkey->uid, (int) $passkey->id)) {
      return $this->error('thessley_already_resolved', 'This request was already resolved.', 409);
    }
    return $this->json(['result' => 'ok']);
  }

  // ---- enrol ---------------------------------------------------------------

  public function enrollStart(): JsonResponse {
    $m = $this->manager;
    $result = $m->store()->createRequest('enroll', (int) $this->currentUser()->id(), PasskeyManager::ENROLL_TTL, $m->clientIp());
    $result['url'] = $m->authUrl('enroll', $result['request_id']);
    $result['app_link'] = $m->appLink('enroll', $result['request_id'], $result['nonce'], $result['ip']);
    return $this->json($result);
  }

  public function enrollStatus(string $id): JsonResponse {
    $store = $this->manager->store();
    $row = $store->getRequest($id);

    if (!$row || $row->type !== 'enroll' || (int) $row->requester_uid !== (int) $this->currentUser()->id()) {
      return $this->error('thessley_not_found', 'Not found.', 404);
    }
    if ($this->expired($row) && $row->status === 'pending') {
      return $this->json(['status' => 'expired']);
    }

    $response = ['status' => $row->status];
    if ($row->status === 'approved' && $row->credential_row) {
      $device = $store->getDevice((int) $row->credential_row);
      $response['label'] = $device ? (string) $device->label : '';
    }
    return $this->json($response);
  }

  /**
   * Optional first step for a device whose key lives in a TPM: prove the chip is genuine.
   * Open like enroll/respond (the pending enrolment request is the capability), rate limited.
   */
  public function enrollTpmChallenge(Request $request, string $id): JsonResponse {
    $m = $this->manager;
    if ($m->rateLimited('enroll_tpm')) {
      return $this->error('thessley_rate_limited', 'Too many requests.', 429);
    }
    $row = $m->store()->getRequest($id);
    if (!$row || $row->type !== 'enroll' || $row->status !== 'pending' || $this->expired($row)) {
      return $this->error('thessley_expired', 'This request is no longer valid.', 409);
    }
    $certs = $this->param($request, 'ek_certs');
    $ak = $this->param($request, 'ak_public');
    if (!is_array($certs) || !is_string($ak) || strlen($ak) > 1024) {
      return $this->error('thessley_bad_request', 'Missing TPM details.', 400);
    }
    $out = $m->tpmChallenge($id, $certs, $ak);
    if (is_string($out)) {
      $m->audit('tpm_challenge_refused', $out, TRUE);
      return $this->error('thessley_tpm_unverified', 'The TPM could not be verified: ' . $out . '.', 400);
    }
    return $this->json($out);
  }

  public function enrollRespond(Request $request, string $id): JsonResponse {
    $m = $this->manager;
    $store = $m->store();

    if ($m->rateLimited('enroll_respond')) {
      return $this->error('thessley_rate_limited', 'Too many requests.', 429);
    }

    $public_key = (string) $this->param($request, 'public_key');
    $algorithm = (string) $this->param($request, 'algorithm');
    $label = trim(preg_replace('/[\x00-\x1F\x7F]+/u', ' ', (string) $this->param($request, 'label')));
    $timestamp = (int) $this->param($request, 'timestamp');
    $proof = (string) $this->param($request, 'proof_signature');
    $chain = $this->param($request, 'attestation_chain');
    $chain = is_array($chain) ? array_values(array_filter($chain, 'is_string')) : [];

    $row = $store->getRequest($id);
    if (!$row || $row->type !== 'enroll' || $row->status !== 'pending' || $this->expired($row)) {
      return $this->error('thessley_expired', 'This request is no longer valid.', 409);
    }
    if (!Crypto::timestamp_fresh($timestamp)) {
      return $this->error('thessley_stale', 'Timestamp out of range.', 401);
    }
    if ($public_key === '' || strlen($public_key) > 255) {
      return $this->error('thessley_bad_request', 'Missing public key.', 400);
    }

    // Proof of possession: signed with the *new* private key over the usual
    // canonical string (type=enroll, action=register).
    $message = Crypto::canonical_string('enroll', $id, $m->origin(), $row->nonce, $timestamp, 'register');
    if (!Crypto::verify($public_key, $message, $proof)) {
      $m->audit('signature_invalid', 'enroll proof-of-possession failed', TRUE);
      return $this->error('thessley_bad_signature', 'Proof of possession failed.', 401);
    }

    $uid = (int) $row->requester_uid;
    $account = $this->loadUser($uid);
    if (!$account || !$account->isActive()) {
      return $this->error('thessley_expired', 'This request is no longer valid.', 409);
    }

    // Claim the request first so two simultaneous responses cannot both add a
    // device; the device row id is filled in afterwards.
    if (!$store->resolveRequest($id, 'approved', $uid)) {
      return $this->error('thessley_already_resolved', 'This request was already resolved.', 409);
    }
    $credential_id = $store->addPasskey($uid, $public_key, $algorithm, $label);
    $row_id = $store->getRowId($credential_id);
    $store->attachDevice($id, $row_id);

    $m->audit('enroll_approved', 'user #' . $uid . ' added device "' . $label . '"');
    $m->notifyDeviceEnrolled($uid, $label);
    // `attestation` is the old field the desktop agents read (a storage name);
    // `attestation_status` is the verdict the phone shows, in the same words as
    // the Linux PAM and Windows AD services. Without it a site entry could only
    // read "not verified" on the phone.
    $level = '';
    $att_status = 'unverified';
    $att_reason = '';
    $tpm = $this->param($request, 'tpm');
    if (is_array($tpm)) {
      $result = $m->verifyTpm($id, $row->nonce, $public_key, $tpm);
      if ($result['ok']) {
        $store->setAttestationLevel($row_id, 'tpm');
        $m->audit('attestation_verified', 'device #' . $row_id . ': tpm (' . trim($result['maker'] . ' ' . $result['model']) . ')');
        $level = 'tpm';
        $att_status = 'verified_tpm';
        $att_reason = 'hardware_attestation_valid';
      }
      else {
        $store->setAttestationLevel($row_id, NULL);
        $m->audit('attestation_unverified', 'device #' . $row_id . ': tpm: ' . $result['reason'], TRUE);
        $att_reason = (string) $result['reason'];
      }
    }
    else {
      $recorded = $m->recordAttestation($row_id, $chain, $row->nonce, $public_key);
      $level = $recorded['level'];
      $att_status = $recorded['status'];
      $att_reason = $recorded['reason'];
    }

    return $this->json([
      'result' => 'ok',
      'credential_id' => $credential_id,
      'username' => $account->getAccountName(),
      'attestation' => $level,
      'attestation_status' => $att_status,
      'attestation_reason' => $att_reason,
    ]);
  }

  // ---- devices -------------------------------------------------------------

  /** Own devices; an administrator may pass ?uid= to list another account's. */
  public function devices(Request $request): JsonResponse {
    $me = $this->currentUser();
    $uid = (int) ($request->query->get('uid') ?: $me->id());
    if ($uid !== (int) $me->id() && !$me->hasPermission('administer thessley passkey')) {
      return $this->error('thessley_not_found', 'Not found.', 404);
    }
    return $this->json(['devices' => $this->deviceRows($uid)]);
  }

  /** Revoke one device. Owner only, or an administrator. */
  public function revoke(Request $request, int $device): JsonResponse {
    $store = $this->manager->store();
    $row = $store->getDevice($device);
    $me = $this->currentUser();
    if (!$row || ((int) $row->uid !== (int) $me->id() && !$me->hasPermission('administer thessley passkey'))) {
      return $this->error('thessley_not_found', 'Not found.', 404);
    }
    $store->revoke($device, (int) $row->uid);
    $this->manager->audit('device_revoked', 'device #' . $device . ' for user #' . $row->uid . ' by user #' . $me->id());
    return $this->json(['result' => 'ok']);
  }

  /** @return array<int,array<string,mixed>> */
  public function deviceRows(int $uid): array {
    $out = [];
    foreach ($this->manager->store()->devicesForUser($uid) as $d) {
      $out[] = [
        'id' => (int) $d->id,
        'label' => (string) $d->label,
        'created' => (int) $d->created,
        'last_used' => $d->last_used ? (int) $d->last_used : NULL,
        'revoked' => $d->revoked ? (int) $d->revoked : NULL,
        'security' => $d->attestation_level ?: 'unverified',
      ];
    }
    return $out;
  }

}
