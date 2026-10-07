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
  public function recordAttestation(int $row_id, array $chain, string $nonce, string $public_key): void {
    $result = Attestation::verify($chain, $nonce, $public_key);
    if (empty($result['ok'])) {
      $this->store->setAttestationLevel($row_id, NULL);
      $this->audit('attestation_unverified', 'device #' . $row_id . ': ' . ($result['reason'] ?? ''));
      return;
    }
    $this->store->setAttestationLevel($row_id, $result['security_level_name']);
    $this->audit('attestation_verified', 'device #' . $row_id . ': ' . $result['security_level_name']);
  }

  /** Event line in the Drupal log (admin/reports/dblog), type thessley_passkey. */
  public function audit(string $event, string $detail = '', bool $warning = FALSE): void {
    $message = '@event @detail (ip @ip)';
    $context = ['@event' => $event, '@detail' => $detail, '@ip' => $this->clientIp()];
    $warning ? $this->logger->warning($message, $context) : $this->logger->notice($message, $context);
  }

}
