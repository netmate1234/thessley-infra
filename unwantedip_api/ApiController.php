<?php

namespace Drupal\unwantedip_api\Controller;

use Drupal\Core\Controller\ControllerBase;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class ApiController extends ControllerBase {

  /**
   * Authenticate via X-API-Key header.
   * Checks field_api_key on all active users.
   * Returns the user account on success, NULL on failure.
   */
  private function authenticate(Request $request): ?\Drupal\user\UserInterface {
    $key = $request->headers->get('X-API-Key');
    if (!$key) return NULL;

    $ids = \Drupal::entityTypeManager()->getStorage('user')->getQuery()
      ->condition('status', 1)
      ->condition('field_api_key', $key)
      ->accessCheck(FALSE)
      ->execute();

    if (empty($ids)) return NULL;
    return \Drupal::entityTypeManager()->getStorage('user')->load(reset($ids));
  }

  // POST /api/v1/signup — register the caller's own IP, get a generated API key back.
  // No body required: identity is the connecting IP itself (real IP resolved via the
  // trusted reverse-proxy config in settings.php, not a client-supplied field).
  public function postSignup(Request $request): JsonResponse {
    $ip = $request->getClientIp();

    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
      return new JsonResponse(['error' => 'Signup requires a public IPv4 address — private/reserved ranges are not accepted.'], 400);
    }

    $user_storage = \Drupal::entityTypeManager()->getStorage('user');
    $existing = $user_storage->getQuery()
      ->condition('name', $ip)
      ->accessCheck(FALSE)
      ->execute();

    if ($existing) {
      return new JsonResponse(['error' => 'An account for this IP already exists. Keys are shown once at signup and cannot be retrieved again — contact the site owner if yours was lost.'], 409);
    }

    $key = bin2hex(random_bytes(24));

    try {
      $user = $user_storage->create([
        'name'          => $ip,
        'mail'          => $ip . '@unwantedip.local',
        'pass'          => bin2hex(random_bytes(32)),
        'status'        => 1,
        'field_api_key' => $key,
      ]);
      $user->save();
    }
    catch (\Exception $e) {
      // Race: another request registered this IP between our check and save.
      return new JsonResponse(['error' => 'An account for this IP already exists.'], 409);
    }

    return new JsonResponse([
      'status'  => 'created',
      'ip'      => $ip,
      'api_key' => $key,
      'note'    => 'Store this key now — it will not be shown again. Send it as the X-API-Key header on /api/v1/report.',
    ], 201);
  }

  // GET /api/v1/ip/{ip}
  public function getIp(Request $request, string $ip): JsonResponse {
    if (!$this->authenticate($request)) {
      return new JsonResponse(['error' => 'Unauthorized. Provide X-API-Key header.'], 401);
    }
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
      return new JsonResponse(['error' => 'Invalid IP address'], 400);
    }

    $storage = \Drupal::entityTypeManager()->getStorage('node');

    $ids = $storage->getQuery()
      ->condition('type', 'ip')
      ->condition('title', $ip)
      ->condition('status', 1)
      ->accessCheck(FALSE)
      ->execute();

    if (empty($ids)) {
      return new JsonResponse(['error' => 'IP not found'], 404);
    }

    $node = $storage->load(reset($ids));
    $result = [
      'id'      => $node->id(),
      'ip'      => $node->getTitle(),
      'created' => date('c', $node->getCreatedTime()),
      'reports' => [],
    ];

    $report_ids = $storage->getQuery()
      ->condition('type', 'ip_report')
      ->condition('field_ip.target_id', $node->id())
      ->condition('status', 1)
      ->accessCheck(FALSE)
      ->sort('created', 'DESC')
      ->execute();

    foreach ($storage->loadMultiple($report_ids) as $report) {
      $result['reports'][] = [
        'id'          => $report->id(),
        'title'       => $report->getTitle(),
        'description' => $report->hasField('field_description') ? $report->get('field_description')->value : NULL,
        'severity'    => $report->hasField('field_severity') ? $report->get('field_severity')->value : NULL,
        'created'     => date('c', $report->getCreatedTime()),
        'author'      => $report->getOwner()->getDisplayName(),
      ];
    }

    return new JsonResponse($result);
  }

  // GET /api/v1/range/{cidr}  — pass slash as - e.g. 192.168.1.0-24
  public function getRange(Request $request, string $cidr): JsonResponse {
    $cidr = str_replace('-', '/', $cidr);

    if (!str_contains($cidr, '/')) {
      return new JsonResponse(['error' => 'Invalid CIDR — use e.g. 192.168.1.0-24'], 400);
    }

    [$network, $prefix] = explode('/', $cidr, 2);
    if (!filter_var($network, FILTER_VALIDATE_IP) || !is_numeric($prefix) || $prefix < 0 || $prefix > 32) {
      return new JsonResponse(['error' => 'Invalid CIDR range'], 400);
    }

    $mask    = ~((1 << (32 - $prefix)) - 1);
    $net_int = ip2long($network) & $mask;
    $bcast   = $net_int | ~$mask;

    $storage = \Drupal::entityTypeManager()->getStorage('node');
    $ids = $storage->getQuery()
      ->condition('type', 'ip')
      ->condition('status', 1)
      ->accessCheck(FALSE)
      ->execute();

    $matches = [];
    foreach ($storage->loadMultiple($ids) as $node) {
      $ip_long = ip2long($node->getTitle());
      if ($ip_long !== FALSE && $ip_long >= $net_int && $ip_long <= $bcast) {
        $matches[] = [
          'id'      => $node->id(),
          'ip'      => $node->getTitle(),
          'created' => date('c', $node->getCreatedTime()),
        ];
      }
    }

    usort($matches, fn($a, $b) => ip2long($a['ip']) <=> ip2long($b['ip']));

    return new JsonResponse([
      'cidr'  => "$network/$prefix",
      'count' => count($matches),
      'ips'   => $matches,
    ]);
  }

  // GET /api/v1/feed/wordpress — requires valid X-API-Key.
  // Plain-text, one IPv4 per line: IPs behind at least one report in the
  // last 90 days whose title signals WordPress-targeting traffic (xmlrpc,
  // wp-login, wp-admin, wp-content, wp-json, or literally containing
  // "wordpress"). The 90-day window keeps this a "currently active"
  // feed rather than an ever-growing list of addresses that may have
  // been reassigned since — the same reasoning FireHOL's volatile
  // level2 list uses for its own 48h window, just longer since this
  // is fed by report volume rather than a live sensor network.
  public function getWordpressFeed(Request $request): Response {
    if (!$this->authenticate($request)) {
      return new Response("Unauthorized. Provide X-API-Key header.\n", 401, ['Content-Type' => 'text/plain']);
    }

    // Served from Drupal's cache (a database cache bin, never a file under the
    // web root), so it can only be reached through the authenticate() call
    // above. Building it scans ~1M report rows (several seconds); doing that
    // per request exhausted PHP's memory limit and returned HTTP 500 before,
    // and the feed only needs to be as fresh as the plugin's daily refresh.
    $cid = 'unwantedip_api:wordpress_feed';
    $headers = ['Content-Type' => 'text/plain; charset=utf-8', 'Cache-Control' => 'private, max-age=900'];

    if ($cached = \Drupal::cache()->get($cid)) {
      return new Response($cached->data, 200, $headers);
    }

    // One rebuild at a time: concurrent misses wait for the winner's result
    // instead of each running the heavy query.
    $lock = \Drupal::lock();
    if (!$lock->acquire($cid, 120)) {
      $lock->wait($cid, 60);
      if ($cached = \Drupal::cache()->get($cid)) {
        return new Response($cached->data, 200, $headers);
      }
      return new Response("Feed is being rebuilt, retry shortly.\n", 503, ['Content-Type' => 'text/plain', 'Retry-After' => '30']);
    }

    // One join driven from the report table, selecting only the IP title
    // (STRAIGHT_JOIN because the optimizer otherwise starts from the 1M-row
    // field table and takes ~20s; this order takes ~6s). No user input reaches
    // the SQL: every value is a fixed literal or a placeholder.
    $db = \Drupal::database();
    $needles = ['wordpress', 'wp-login', 'wp-admin', 'wp-content', 'wp-json', 'xmlrpc'];
    $likes = [];
    $args = [':since' => strtotime('-90 days')];
    foreach ($needles as $i => $needle) {
      $likes[] = "r.title LIKE :n$i";
      $args[":n$i"] = '%' . $db->escapeLike($needle) . '%';
    }
    $sql = "SELECT DISTINCT ip.title FROM {node_field_data} r "
      . "STRAIGHT_JOIN {node__field_ip} fi ON fi.entity_id = r.nid AND fi.deleted = 0 "
      . "STRAIGHT_JOIN {node_field_data} ip ON ip.nid = fi.field_ip_target_id "
      . "WHERE r.type = 'ip_report' AND r.status = 1 AND r.created >= :since AND (" . implode(' OR ', $likes) . ") "
      . "ORDER BY ip.title";

    try {
      $ips = $db->query($sql, $args)->fetchCol();
      $body = $ips ? implode("\n", $ips) . "\n" : '';
      \Drupal::cache()->set($cid, $body, time() + 6 * 3600);
    }
    finally {
      $lock->release($cid);
    }

    return new Response($body, 200, $headers);
  }

  // POST /api/v1/report  — requires valid X-API-Key
  public function postReport(Request $request): JsonResponse {
    $user = $this->authenticate($request);
    if (!$user) {
      return new JsonResponse(['error' => 'Unauthorized — invalid or missing X-API-Key'], 401);
    }

    $body = json_decode($request->getContent(), TRUE);
    if (!$body) {
      return new JsonResponse(['error' => 'Invalid JSON body'], 400);
    }

    $ip_value    = $body['ip'] ?? NULL;
    $title       = $body['title'] ?? NULL;
    $description = $body['description'] ?? NULL;
    $severity    = $body['severity'] ?? NULL;

    if (!$ip_value || !$title) {
      return new JsonResponse(['error' => 'Required fields: ip, title'], 400);
    }

    if (!filter_var($ip_value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
      return new JsonResponse(['error' => 'Invalid IP address'], 400);
    }

    // Never report whitelisted/infrastructure IPs
    $protected = ['88.99.89.155','91.99.140.27','192.168.1.200','192.168.1.79','82.67.210.182'];
    if (in_array($ip_value, $protected)) {
      return new JsonResponse(['status' => 'whitelisted', 'ip' => $ip_value], 200);
    }

    $storage = \Drupal::entityTypeManager()->getStorage('node');

    // Find or create IP node
    $ip_ids = $storage->getQuery()
      ->condition('type', 'ip')
      ->condition('title', $ip_value)
      ->accessCheck(FALSE)
      ->execute();

    if ($ip_ids) {
      $ip_node = $storage->load(reset($ip_ids));
    }
    else {
      $ip_node = $storage->create([
        'type'   => 'ip',
        'title'  => $ip_value,
        'status' => 1,
        'uid'    => $user->id(),
      ]);
      $ip_node->save();
      // Fetch GeoIP once when the IP is first seen — no runtime calls on page view.
      _unwantedip_api_fetch_geoip($ip_value);
      // Ping IndexNow (Bing/Yandex/Seznam/Naver) for instant indexing.
      _unwantedip_api_indexnow_ping($ip_value);
    }

    // Create report owned by the authenticated user
    $report_data = [
      'type'     => 'ip_report',
      'title'    => $title,
      'status'   => 1,
      'uid'      => $user->id(),
      'field_ip' => ['target_id' => $ip_node->id()],
    ];
    if ($description) {
      $report_data['field_description'] = ['value' => $description, 'format' => 'plain_text'];
    }
    if ($severity && in_array($severity, ['low', 'medium', 'high', 'critical'])) {
      $report_data['field_severity'] = $severity;
    }

    // Deduplicate: reject if same IP + description + same minute already exists
    if ($description) {
      $dup_minute = strtotime(date('Y-m-d H:i:00'));
      $dup = $storage->getQuery()
        ->condition('type', 'ip_report')
        ->condition('field_ip.target_id', $ip_node->id())
        ->condition('field_description', $description)
        ->condition('created', $dup_minute, '>=')
        ->accessCheck(FALSE)
        ->range(0, 1)
        ->execute();
      if ($dup) {
        return new JsonResponse(['status' => 'duplicate', 'ip' => $ip_value], 200);
      }
    }

    $report = $storage->create($report_data);
    $report->save();

    $threat = _unwantedip_api_compute_threat($ip_node->id());
    _unwantedip_api_save_threat_fields($ip_node->id(), $threat);

    return new JsonResponse([
      'status'    => 'created',
      'report_id' => $report->id(),
      'ip_id'     => $ip_node->id(),
      'ip'        => $ip_value,
      'author'    => $user->getDisplayName(),
    ], 201);
  }

}
