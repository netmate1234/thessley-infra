<?php

namespace Drupal\thessley_passkey\PathProcessor;

use Drupal\Core\PathProcessor\InboundPathProcessorInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Maps the WordPress-style REST fallback onto this module's real routes.
 *
 * The Android app builds every call as
 *   {origin}/?rest_route=/thessley/v1/passkey/login/start
 * because that form always works on WordPress. It is kept as is so the same
 * app works against Drupal; this turns that request into the real path
 * /thessley/v1/passkey/login/start before routing. Only that exact prefix is
 * accepted — any other rest_route value is left alone.
 */
class RestRoutePathProcessor implements InboundPathProcessorInterface {

  private const PREFIX = '/thessley/v1/passkey/';

  public function processInbound($path, Request $request) {
    if ($path !== '/' && $path !== '/index.php') {
      return $path;
    }
    $route = $request->query->get('rest_route');
    if (!is_string($route)) {
      return $path;
    }
    // Only plain path characters: no dots, no traversal, no encoded tricks.
    if (strpos($route, self::PREFIX) === 0 && preg_match('#^/thessley/v1/passkey/[A-Za-z0-9_/-]+$#', $route) && strpos($route, '//') === FALSE) {
      return $route;
    }
    return $path;
  }

}
