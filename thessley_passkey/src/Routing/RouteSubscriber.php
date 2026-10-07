<?php

namespace Drupal\thessley_passkey\Routing;

use Drupal\Core\Routing\RouteSubscriberBase;
use Symfony\Component\Routing\RouteCollection;

/**
 * Closes the password-only back door in core's JSON login.
 *
 * POST /user/login?_format=json checks the password and logs in without ever
 * touching the login form, so it would sidestep both "Password, then app" and
 * "App only". Whenever the site mode is not 'optional' that route is given an
 * access check that refuses it.
 */
class RouteSubscriber extends RouteSubscriberBase {

  protected function alterRoutes(RouteCollection $collection) {
    if ($route = $collection->get('user.login.http')) {
      $route->setRequirement('_thessley_passkey_json_login', 'TRUE');
    }
  }

}
