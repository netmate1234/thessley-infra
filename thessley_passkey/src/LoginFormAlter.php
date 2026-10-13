<?php

namespace Drupal\thessley_passkey;

use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Render\Markup;
use Drupal\Core\Url;
use Symfony\Component\HttpFoundation\RedirectResponse;

/**
 * Wires Passkey Login into /user/login: the QR box beneath the form, and the
 * server-side rules for 'Password, then app' and 'App only'.
 */
class LoginFormAlter {

  /** Query flag that keeps the password form visible in 'App only' mode (accounts with a device are still refused server-side). */
  const HATCH = 'thessley_password';

  public static function alter(array &$form, FormStateInterface $form_state): void {
    /** @var \Drupal\thessley_passkey\PasskeyManager $m */
    $m = \Drupal::service('thessley_passkey.manager');
    $mode = $m->mode();

    // Always, in every mode: the server decides after the password is right.
    $form['#validate'][] = [static::class, 'validate'];
    $form['#cache']['tags'][] = 'config:thessley_passkey.settings';
    $form['#cache']['contexts'][] = 'url.query_args:' . self::HATCH;

    if ($mode === '2fa') {
      return;
    }

    $hatch = \Drupal::request()->query->get(self::HATCH) === '1';
    $identify = $m->identify();
    $optional = $mode === 'optional';

    if ($mode === 'required' && !$hatch) {
      $form['#attributes']['class'][] = 'thessley-pk-hidden';
    }
    if ($identify && $optional) {
      // Hidden by a class only a script adds, so a browser without JS keeps
      // the normal password form instead of being locked out of it.
      $form['#attached']['html_head'][] = [[
        '#type' => 'html_tag',
        '#tag' => 'script',
        '#value' => 'document.documentElement.classList.add("thessley-pk-step1");',
      ], 'thessley_passkey_step1'];
    }

    $box = [
      '#theme' => 'thessley_passkey_login_box',
      '#identify' => $identify,
      '#optional' => $optional,
    ];
    $html = (string) \Drupal::service('renderer')->renderInIsolation($box);
    $form['#suffix'] = Markup::create(($form['#suffix'] ?? '') . $html);

    $form['#attached']['library'][] = 'thessley_passkey/login';
    $form['#attached']['drupalSettings']['thessleyPasskeyLogin'] = [
      'start' => Url::fromRoute('thessley_passkey.login_start')->toString(),
      'status' => Url::fromRoute('thessley_passkey.login_status', ['id' => '__ID__'])->toString(),
      'identify' => $identify,
      'optional' => $optional,
    ];
  }

  /**
   * Runs after core's own validators, so the password is already known to be
   * right: only then does the account's mode matter. A wrong password still
   * gets Drupal's normal message.
   */
  public static function validate(array &$form, FormStateInterface $form_state): void {
    if ($form_state->hasAnyErrors() || !($uid = (int) $form_state->get('uid'))) {
      return;
    }
    /** @var \Drupal\thessley_passkey\PasskeyManager $m */
    $m = \Drupal::service('thessley_passkey.manager');
    $mode = $m->effectiveModeForUser($uid);

    if ($mode === 'required') {
      $m->audit('password_login_blocked', 'user #' . $uid . ' - passkey-only', TRUE);
      $form_state->setErrorByName('name', t('Password login is disabled for this account. Use the Thessley Passkey app to log in.'));
      return;
    }

    if ($mode === '2fa') {
      // The password was right but login is not finished: swap the normal
      // submit (which would log in) for one that sends the browser to the
      // app-confirmation page, bound to this exact account.
      $form_state->set('thessley_passkey_2fa_uid', $uid);
      $form_state->setSubmitHandlers([[static::class, 'submit2fa']]);
    }
  }

  public static function submit2fa(array &$form, FormStateInterface $form_state): void {
    /** @var \Drupal\thessley_passkey\PasskeyManager $m */
    $m = \Drupal::service('thessley_passkey.manager');
    $uid = (int) $form_state->get('thessley_passkey_2fa_uid');
    $result = $m->store()->createRequest('2fa', $uid, PasskeyManager::LOGIN_TTL, $m->clientIp());
    $m->audit('password_step_ok', 'user #' . $uid . ' - awaiting Thessley Passkey app confirmation');

    $response = new RedirectResponse(Url::fromRoute('thessley_passkey.auth_page', ['type' => '2fa', 'id' => $result['request_id']])->toString());
    $response->headers->setCookie($m->bindBrowser($result['request_id']));
    $form_state->setResponse($response);
  }

}
