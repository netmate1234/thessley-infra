# unwantedip_api / ApiController.php

Copy of `src/Controller/ApiController.php` from the `unwantedip_api` custom Drupal
module on the OPi5 host (`/var/www/unwantedip/web/modules/custom/unwantedip_api/`),
kept here for version control only. The site itself is not part of this repo;
deploy by copying this file back to that path.

## 2026-09-26: `getWordpressFeed()` rewritten

`GET /api/v1/feed/wordpress` returned HTTP 500 (PHP memory limit, 256M) because it
loaded every matching report id and then every distinct IP node as a full entity
(~1M report rows). The plugin treated the 500 as "nothing to fetch", so the feed
silently disappeared from the IP Blocklist "Reputation feeds" table.

Now:

- The `X-API-Key` check runs first; a missing, empty or wrong key gets 401 before the
  cache is touched.
- The feed is cached in Drupal's `cache_default` bin (`unwantedip_api:wordpress_feed`,
  6 h), never as a file under the web root, so it is only reachable through the
  authenticated handler. Concurrent cache misses wait on a lock instead of each
  running the query.
- The query is one `STRAIGHT_JOIN` starting from the report table (~6 s instead of
  ~22 s), selecting only the IP title.

To force a rebuild: `drush cache:get`/`ev '\Drupal::cache()->delete("unwantedip_api:wordpress_feed");'`
(or `drush cr`).
