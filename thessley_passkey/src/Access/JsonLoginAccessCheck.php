<?php

namespace Drupal\thessley_passkey\Access;

use Drupal\Core\Access\AccessResult;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Routing\Access\AccessInterface;

/**
 * Denies core's password-only JSON login unless the site mode is 'optional'.
 */
class JsonLoginAccessCheck implements AccessInterface {

  public function __construct(protected ConfigFactoryInterface $configFactory) {}

  public function access() {
    $config = $this->configFactory->get('thessley_passkey.settings');
    $mode = $config->get('mode');
    return $mode === '2fa' || $mode === 'required'
      ? AccessResult::forbidden('Password-only JSON login is disabled while Passkey Login requires the app.')->addCacheableDependency($config)
      : AccessResult::allowed()->addCacheableDependency($config);
  }

}
