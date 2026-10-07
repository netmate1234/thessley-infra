<?php

namespace Drupal\thessley_passkey\Controller;

use Drupal\Core\Access\AccessResult;
use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Session\AccountInterface;
use Drupal\Core\Url;
use Drupal\thessley_passkey\PasskeyManager;
use Drupal\user\UserInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpKernel\Exception\GoneHttpException;

/**
 * The human-facing pages: the "confirm with the app" step that follows a
 * password in 'Password, then app' mode, the fallback page behind a QR's
 * https URL, and the per-account device list.
 */
class PageController extends ControllerBase {

  public function __construct(protected PasskeyManager $manager) {}

  public static function create(ContainerInterface $container) {
    return new static($container->get('thessley_passkey.manager'));
  }

  public function authPage(string $type, string $id): array {
    $m = $this->manager;
    $row = $m->store()->getRequest($id);

    if (!$row || $row->type !== $type || $m->store()->isExpired($row) || !in_array($row->status, ['pending', 'approved'], TRUE)) {
      throw new GoneHttpException('This login/enrollment request has expired. Go back and try again.');
    }

    if ($type !== '2fa') {
      // Only a human who opened the QR's URL some other way lands here; the
      // app itself never uses this page.
      return [
        '#markup' => $this->t('Open this on the device with the Thessley Passkey app installed to continue.'),
        '#cache' => ['max-age' => 0],
      ];
    }

    $account = $row->requester_uid ? $this->entityTypeManager()->getStorage('user')->load((int) $row->requester_uid) : NULL;
    $app_link = $m->appLink('2fa', $row->request_id, $row->nonce, (string) $row->ip, $account instanceof UserInterface ? $account->getAccountName() : '');

    return [
      '#theme' => 'thessley_passkey_confirm',
      '#app_link' => $app_link,
      '#attached' => [
        'library' => ['thessley_passkey/confirm'],
        'drupalSettings' => ['thessleyPasskey' => [
          'appLink' => $app_link,
          'status' => Url::fromRoute('thessley_passkey.login_status', ['id' => $row->request_id])->toString(),
          'login' => Url::fromRoute('user.login')->toString(),
        ]],
      ],
      '#cache' => ['max-age' => 0],
    ];
  }

  public function userDevicesAccess(AccountInterface $account, UserInterface $user): AccessResult {
    $own = (int) $account->id() === (int) $user->id() && $account->hasPermission('use thessley passkey');
    return AccessResult::allowedIf($own || $account->hasPermission('administer thessley passkey'))
      ->cachePerPermissions()->cachePerUser()->addCacheableDependency($user);
  }

  public function userDevices(UserInterface $user): array {
    $me = $this->currentUser();
    $own = (int) $me->id() === (int) $user->id();
    $api = \Drupal::classResolver(ApiController::class);

    return [
      '#theme' => 'thessley_passkey_devices',
      '#can_enroll' => $own && $me->hasPermission('use thessley passkey'),
      '#hint' => [
        'optional' => $this->t('Add a new device to sign in without a password.'),
        '2fa' => $this->t('Add a new device to confirm logins with, after your password.'),
        'required' => $this->t('Add a new device — the app is the only way to sign in.'),
      ][$this->manager->mode()],
      '#attached' => [
        'library' => ['thessley_passkey/devices'],
        'drupalSettings' => ['thessleyPasskey' => [
          'uid' => (int) $user->id(),
          'devices' => $api->deviceRows((int) $user->id()),
          'urls' => [
            'token' => Url::fromRoute('system.csrftoken')->toString(),
            'devices' => Url::fromRoute('thessley_passkey.devices')->toString(),
            'enrollStart' => Url::fromRoute('thessley_passkey.enroll_start')->toString(),
            'enrollStatus' => Url::fromRoute('thessley_passkey.enroll_status', ['id' => '__ID__'])->toString(),
            'revoke' => Url::fromRoute('thessley_passkey.revoke', ['device' => 0])->toString(),
          ],
        ]],
      ],
      '#cache' => ['max-age' => 0],
    ];
  }

}
