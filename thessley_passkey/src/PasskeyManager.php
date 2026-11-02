<?php

namespace Drupal\thessley_passkey;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Flood\FloodInterface;
use Drupal\Core\KeyValueStore\KeyValueExpirableFactoryInterface;
use Drupal\Core\Language\LanguageManagerInterface;
use Drupal\Core\Mail\MailManagerInterface;
use Drupal\user\UserInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Policy and glue for Passkey Login: the site mode, who may do what, the
 * app link, browser binding, rate limiting and the enrolment notice.
 */
class PasskeyManager {

  const LOGIN_TTL = 120;
  const ENROLL_TTL = 120;
  const RATE_LIMIT_MAX = 20;
  const RATE_LIMIT_WINDOW = 600;
  const BIND_COOKIE = 'thessley_pk_bt';
  const MODES = ['optional', '2fa', 'required'];

  public function __construct(
    protected ConfigFactoryInterface $configFactory,
    protected PasskeyStore $store,
    protected KeyValueExpirableFactoryInterface $keyValue,
    protected FloodInterface $flood,
    protected RequestStack $requestStack,
    protected TimeInterface $time,
    protected LoggerInterface $logger,
    protected EntityTypeManagerInterface $entityTypeManager,
    protected MailManagerInterface $mailManager,
    protected LanguageManagerInterface $languageManager,
  ) {}

  public function store(): PasskeyStore {
    return $this->store;
  }

  /**
   * optional: password form and QR together. 2fa: password, then the app.
   * required: the app only. One site-wide setting — deliberately no
   * per-account override that could drift away from what the page shows.
   */
  public function mode(): string {
    $mode = $this->configFactory->get('thessley_passkey.settings')->get('mode');
    return in_array($mode, self::MODES, TRUE) ? $mode : 'optional';
  }

  /**
   * Whether the login page asks for the username first. Ignored in '2fa',
   * where the password step already identifies the account. Enforced
   * server-side: while on, /login/start refuses a request without a
   * username, and that request can only be approved by that account's own
   * devices.
   */
  public function identify(): bool {
    return $this->mode() !== '2fa' && (bool) $this->configFactory->get('thessley_passkey.settings')->get('identify');
  }

  /** What applies to this account now: the site mode, unless it has no device yet (nothing to require without one). */
  public function effectiveModeForUser(int $uid): string {
    if (!$this->store->hasActiveDevice($uid)) {
      return 'optional';
    }
    // An account that may no longer use the app falls back to its password.
    $account = $this->entityTypeManager->getStorage('user')->load($uid);
    if (!$account instanceof UserInterface || !$account->hasPermission('use thessley passkey')) {
      return 'optional';
    }
    return $this->mode();
  }

  protected function request(): ?Request {
    return $this->requestStack->getCurrentRequest();
  }

  public function clientIp(): string {
    return (string) ($this->request()?->getClientIp() ?? '');
  }

  /** The origin signed into every approval and given to the app. Never client-supplied. */
  public function origin(): string {
    $override = trim((string) $this->configFactory->get('thessley_passkey.settings')->get('origin'));
    if ($override !== '') {
      return rtrim($override, '/');
    }
    $request = $this->request();
    return $request ? $request->getSchemeAndHttpHost() . $request->getBasePath() : '';
  }

  /** True when the caller has used up its allowance on this bucket. */
  public function rateLimited(string $bucket): bool {
    $name = 'thessley_passkey.' . $bucket;
    $ip = $this->clientIp();
    if (!$this->flood->isAllowed($name, self::RATE_LIMIT_MAX, self::RATE_LIMIT_WINDOW, $ip)) {
      return TRUE;
    }
    $this->flood->register($name, self::RATE_LIMIT_WINDOW, $ip);
    return FALSE;
  }

  /** Custom-scheme payload for the QR and the same-device button. */
  public function appLink(string $type, string $request_id, string $nonce, string $ip = '', string $username = ''): string {
    $params = [
      'type' => $type,
      'id' => $request_id,
      'nonce' => $nonce,
      'origin' => $this->origin(),
    ];
    if ($ip !== '') {
      $params['ip'] = $ip;
    }
    if ($username !== '') {
      $params['username'] = $username;
    }
    return 'thessleypasskey://auth?' . http_build_query($params);
  }

  /** The QR-less human page for a request (2fa confirmation, or a fallback for login/enroll). */
  public function authUrl(string $type, string $request_id): string {
    return $this->origin() . '/thessley-auth/' . rawurlencode($type) . '/' . rawurlencode($request_id);
  }

  // ---- Browser binding (login-CSRF guard) --------------------------------

  /**
   * Binds the browser that started a request to it. Only that browser may
   * later receive the session when the device approves, so a request id
   * forced into someone else's browser (e.g. via an <img>) cannot plant the
   * attacker's login there.
   */
  public function bindBrowser(string $request_id): Cookie {
    $token = bin2hex(random_bytes(16));
    $this->keyValue->get('thessley_passkey_bind')->setWithExpire($request_id, $token, self::LOGIN_TTL + 30);
    $request = $this->request();
    return new Cookie(
      self::BIND_COOKIE,
      $token,
      $this->time->getRequestTime() + self::LOGIN_TTL + 30,
      '/',
      NULL,
      $request ? $request->isSecure() : FALSE,
      TRUE,
      FALSE,
      Cookie::SAMESITE_STRICT
    );
  }

  public function browserMatches(string $request_id, Request $request): bool {
    $expected = $this->keyValue->get('thessley_passkey_bind')->get($request_id);
    $actual = $request->cookies->get(self::BIND_COOKIE);
    return is_string($expected) && $expected !== '' && is_string($actual) && $actual !== '' && hash_equals($expected, $actual);
  }

  public function forgetBinding(string $request_id): void {
    $this->keyValue->get('thessley_passkey_bind')->delete($request_id);
  }

  // ---- Notices / audit ----------------------------------------------------

  /**
   * The tripwire against a hijacked session being used to enrol a persistent
   * backdoor device: the real owner is told by email.
   */
  public function notifyDeviceEnrolled(int $uid, string $label): void {
    $account = $this->entityTypeManager->getStorage('user')->load($uid);
    if (!$account instanceof UserInterface || !$account->getEmail()) {
      return;
    }
    $this->mailManager->mail('thessley_passkey', 'device_enrolled', $account->getEmail(), $account->getPreferredLangcode(), [
      'label' => $label,
      'account' => $account,
      'ip' => $this->clientIp(),
      'origin' => $this->origin(),
    ]);
  }

  /**
   * Verifies the Keystore attestation chain and records the result. Never
   * rejects enrolment on it: visibility only, same as the WordPress module.
   */
  /**
   * Verify the device's Keystore chain and record where the key lives.
   *
   * @return array{level:string,status:string,reason:string}
   *   The storage name, the verdict word shared with the PAM and AD services,
   *   and why. Nothing here rejects the enrolment; it is visibility.
   */
  public function recordAttestation(int $row_id, array $chain, string $nonce, string $public_key): array {
    $result = Attestation::verify($chain, $nonce, $public_key);
    if (empty($result['ok'])) {
      $this->store->setAttestationLevel($row_id, NULL);
      $this->audit('attestation_unverified', 'device #' . $row_id . ': ' . ($result['reason'] ?? ''));
      return ['level' => '', 'status' => 'unverified', 'reason' => (string) ($result['reason'] ?? '')];
    }
    $level = (string) $result['security_level_name'];
    $this->store->setAttestationLevel($row_id, $level);
    $this->audit('attestation_verified', 'device #' . $row_id . ': ' . $level);
    return ['level' => $level, 'status' => self::attestationStatus($level), 'reason' => 'hardware_attestation_valid'];
  }

  /**
   * The verdict words the phone already understands from the Linux PAM and
   * Windows AD services: the same sentence for a site, a PC and a VPN.
   */
  public static function attestationStatus(string $level): string {
    switch ($level) {
      case 'tee':
        return 'verified_tee';

      case 'strongbox':
        return 'verified_strongbox';

      case 'software':
        return 'verified_software';

      case 'tpm':
        return 'verified_tpm';
    }
    return 'unverified';
  }

  // ---- TPM hardware attestation ---------------------------------------------------------

  const TPM_CHALLENGE_TTL = 300;

  /** The TPM manufacturer roots we trust: every tpm-roots/*.pem shipped with the module. */
  public function tpmRootFiles(): array {
    $dir = DRUPAL_ROOT . '/' . \Drupal::service('extension.list.module')->getPath('thessley_passkey') . '/tpm-roots';
    return glob($dir . '/*.pem') ?: [];
  }

  /**
   * Step 1 of a TPM-backed enrolment: check the chip's certificate chain and issue the activation challenge.
   *
   * @return array{credential_blob:string,secret:string}|string
   *   The challenge to send back (base64), or a short reason it was refused.
   */
  public function tpmChallenge(string $request_id, array $ek_certs_b64, string $ak_public_b64) {
    $certs = [];
    foreach ($ek_certs_b64 as $c) {
      $der = is_string($c) ? base64_decode($c, TRUE) : FALSE;
      if ($der === FALSE) {
        return 'bad certificate';
      }
      $certs[] = $der;
    }
    $ak = base64_decode($ak_public_b64, TRUE);
    if ($ak === FALSE || $ak === '') {
      return 'bad attestation key';
    }
    $ek = Tpm::verifyEkChain($certs, $this->tpmRootFiles());
    if ($ek === NULL) {
      return 'the TPM certificate chain is not one we trust';
    }
    try {
      $akInfo = Tpm::parsePublic($ak);
      $need = Tpm::ATTR_FIXEDTPM | Tpm::ATTR_FIXEDPARENT | Tpm::ATTR_RESTRICTED | Tpm::ATTR_SIGN;
      if (($akInfo['attributes'] & $need) !== $need) {
        return 'attestation key is not a restricted signing key';
      }
      $secret = random_bytes(32);
      $cred = Tpm::makeCredential($ek['x'], $ek['y'], Tpm::name($ak), $secret);
    }
    catch (\Throwable $e) {
      return 'could not build the challenge';
    }
    $this->keyValue->get('thessley_passkey_tpm')->setWithExpire($request_id, [
      'ak' => hash('sha256', $ak),
      'secret' => hash('sha256', $secret),
      'maker' => $ek['manufacturer'],
      'model' => $ek['model'],
    ], self::TPM_CHALLENGE_TTL);
    return ['credential_blob' => base64_encode($cred['credential_blob']), 'secret' => base64_encode($cred['secret'])];
  }

  /**
   * Step 2: check the device's proof that its signing key lives in that TPM.
   *
   * @return array{ok:bool,reason?:string,maker?:string,model?:string}
   */
  public function verifyTpm(string $request_id, string $nonce, string $public_key_b64, array $t): array {
    $store = $this->keyValue->get('thessley_passkey_tpm');
    $state = $store->get($request_id);
    $store->delete($request_id);  // one challenge, one attempt
    if (!is_array($state)) {
      return ['ok' => FALSE, 'reason' => 'no challenge was issued'];
    }
    $f = static fn($k) => isset($t[$k]) && is_string($t[$k]) ? base64_decode($t[$k], TRUE) : FALSE;
    $ak = $f('ak_public');
    $activated = $f('activated_secret');
    $attest = $f('certify_info');
    $sig = $f('certify_signature');
    $keyPublic = $f('key_public');
    $spki = base64_decode($public_key_b64, TRUE);
    if (in_array(FALSE, [$ak, $activated, $attest, $sig, $keyPublic, $spki], TRUE)) {
      return ['ok' => FALSE, 'reason' => 'incomplete proof'];
    }
    if (!hash_equals($state['ak'], hash('sha256', $ak))) {
      return ['ok' => FALSE, 'reason' => 'a different attestation key than the one challenged'];
    }
    if (!hash_equals($state['secret'], hash('sha256', $activated))) {
      return ['ok' => FALSE, 'reason' => 'activation secret does not match (the key and the TPM certificate are not in the same chip)'];
    }
    $reason = Tpm::verifyCertification($ak, $attest, $sig, $keyPublic, $nonce, $spki);
    if ($reason !== NULL) {
      return ['ok' => FALSE, 'reason' => $reason];
    }
    return ['ok' => TRUE, 'maker' => $state['maker'], 'model' => $state['model']];
  }

  /** Event line in the Drupal log (admin/reports/dblog), type thessley_passkey. */
  public function audit(string $event, string $detail = '', bool $warning = FALSE): void {
    $message = '@event @detail (ip @ip)';
    $context = ['@event' => $event, '@detail' => $detail, '@ip' => $this->clientIp()];
    $warning ? $this->logger->warning($message, $context) : $this->logger->notice($message, $context);
  }

}
