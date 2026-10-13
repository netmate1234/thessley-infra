<?php

namespace Drupal\thessley_passkey\Form;

use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Url;

/**
 * Site-wide Passkey Login settings.
 */
class SettingsForm extends ConfigFormBase {

  protected function getEditableConfigNames() {
    return ['thessley_passkey.settings'];
  }

  public function getFormId() {
    return 'thessley_passkey_settings';
  }

  public function buildForm(array $form, FormStateInterface $form_state) {
    $config = $this->config('thessley_passkey.settings');

    $form['mode'] = [
      '#type' => 'radios',
      '#title' => $this->t('Login method'),
      '#default_value' => $config->get('mode') ?: 'optional',
      '#options' => [
        'optional' => $this->t('Password or the Thessley Passkey app — password form and QR shown together'),
        '2fa' => $this->t('Password, then the Thessley Passkey app — password first, the app then confirms it'),
        'required' => $this->t('Thessley Passkey app only — QR only, no password form'),
      ],
      '#description' => $this->t('Applies to every account with a device enrolled. An account with no device yet always falls back to its password — there is nothing to confirm with yet. Accounts need the "Use Thessley Passkey" permission to enrol a device.'),
    ];

    $form['identify'] = [
      '#type' => 'radios',
      '#title' => $this->t('Username prompt'),
      '#default_value' => $config->get('identify') ? 1 : 0,
      '#options' => [
        0 => $this->t('Not asked — the QR is shown straight away, and the Thessley Passkey app works out who you are'),
        1 => $this->t('Ask for the username first — then show the QR for that account'),
      ],
      '#description' => $this->t('For "Password or the Thessley Passkey app" and "Thessley Passkey app only". With the prompt, step 1 is just a username box; step 2 shows the QR (and, for "Password or the Thessley Passkey app", the password form with the username filled in). Only that account\'s own devices can then approve the QR, and an unknown username looks exactly like a real one. Not used by "Password, then the Thessley Passkey app": the password step already tells the site who you are.'),
      '#states' => ['disabled' => [':input[name="mode"]' => ['value' => '2fa']]],
    ];

    $form['origin'] = [
      '#type' => 'url',
      '#title' => $this->t('Public site URL'),
      '#default_value' => $config->get('origin'),
      '#description' => $this->t('Leave empty to use the address of the request (recommended, with trusted_host_patterns set in settings.php). Set it, without a trailing slash, only if the site sits behind a proxy that hides the real address. This exact value is what the app signs; it must match the address people enrolled their phone with.'),
    ];

    $form['recovery'] = [
      '#type' => 'details',
      '#title' => $this->t('If you get locked out'),
      '#markup' => $this->t('From the server: <code>drush config:set thessley_passkey.settings mode optional</code>, or <code>drush uli</code> for a one-time login link. In "Thessley Passkey app only" mode the password form is hidden, but <a href=":hatch">:hatch</a> shows it; accounts that already have a device are still refused a password login.', [
        ':hatch' => Url::fromRoute('user.login', [], ['query' => ['thessley_password' => 1]])->toString(),
      ]),
    ];

    return parent::buildForm($form, $form_state);
  }

  public function validateForm(array &$form, FormStateInterface $form_state) {
    $origin = trim((string) $form_state->getValue('origin'));
    if ($origin !== '' && !preg_match('#^https?://[^/]+(/[^?\#]*)?$#', $origin)) {
      $form_state->setErrorByName('origin', $this->t('Enter a plain address such as https://example.com.'));
    }
    parent::validateForm($form, $form_state);
  }

  public function submitForm(array &$form, FormStateInterface $form_state) {
    $mode = $form_state->getValue('mode');
    $config = $this->config('thessley_passkey.settings')
      ->set('mode', in_array($mode, ['optional', '2fa', 'required'], TRUE) ? $mode : 'optional')
      ->set('origin', rtrim(trim((string) $form_state->getValue('origin')), '/'));
    // Disabled radios are not submitted: keep the saved choice then.
    if ($form_state->hasValue('identify') && $mode !== '2fa') {
      $config->set('identify', (bool) $form_state->getValue('identify'));
    }
    $config->save();
    parent::submitForm($form, $form_state);
  }

}
