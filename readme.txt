=== Simple IP Rate Limiter ===
Contributors: anna
Tags: security, rate limit, anti-scraping, block ip, bot protection, honeypot
Requires at least: 5.2
Tested up to: 6.6
Stable tag: 1.5.0
License: GPLv2 or later

Anti-scraping rate limiter for WordPress. Blocks abusive IPs by request
threshold, bad User-Agents, honeypot trap URL, or hits on scraping-prone
endpoints (wp-json, feeds). Supports trusted proxies (incl. Cloudflare),
IPv4/IPv6 CIDR whitelist, exponential ban escalation, DB-backed ban log,
atomic counters via object cache, and safe .htaccess sync.

== Description ==

**Detection layers** (each can be enabled/disabled independently):

1. **Request rate per IP** — fixed-window counter per IP; configurable limit
   and window. Atomic increments via persistent object cache
   (Redis / Memcached / APCu) when available; transients otherwise.
2. **Strict rate per endpoint** — tighter limit for scraping-prone paths
   like `/wp-json/`, `/feed`, `/xmlrpc.php`. Requests with a `?feed=` query
   are always treated as strict.
3. **User-Agent blocklist** — bans requests with bot-like UAs
   (python-requests, curl/, Go-http-client, HeadlessChrome, Scrapy, etc.).
   Supports substring match and `~regex~` syntax. Optional "block empty UA".
4. **Honeypot URL** — any hit to a configured path (default `/trap-bot`)
   triggers an instant ban. An invisible `<a>` link is auto-injected into
   the frontend footer so scrapers following every link get caught; real
   users never see it. Optional `Disallow` entry in robots.txt.
5. **Exponential escalation** — each IP has an offense counter. Default
   ladder: first ban 30 min, second 6 h, third and later 7 days. Counter
   resets after 30 days of no bans.

**Logging & auditing:**

- Dedicated `wp_sirl_log` table with ip / ua / path / reason / offense /
  ban_minutes / created_at.
- Admin sub-page "IP Rate Limiter — Logs" with IP filter and pagination.
- Daily WP-Cron task prunes old entries (retention is configurable).

**Safety & correctness:**

- Proper client-IP resolution: X-Forwarded-For / X-Real-IP / CF-Connecting-IP
  are trusted only when the request comes from a configured trusted proxy
  (or bundled Cloudflare ranges when "Behind Cloudflare" is checked).
- IPv4/IPv6 whitelist with full CIDR support (/32, /24, /16, /48, etc.).
- `.htaccess` sync uses WordPress' `insert_with_markers()` with flock for
  atomic, concurrency-safe writes.
- Site admins (`manage_options`), WP-CLI and WP-Cron requests always bypass.

== Upgrade Notice ==

= 1.5.0 =
Adds UA blocklist, honeypot, strict per-endpoint limits, exponential
escalation, and a DB-backed ban log. The new ladder defaults are
30 min → 6 h → 7 days — review settings after upgrade.

= 1.4.0 =
Security & correctness rewrite — read the changelog before upgrading.

== Changelog ==

= 1.5.0 =
* New: User-Agent blocklist (substring + regex). Matching requests are banned.
* New: Honeypot URL with instant ban, hidden footer link, and optional
  robots.txt advertisement.
* New: Separate stricter rate limit for scraping-prone endpoints
  (/wp-json/, /feed, /xmlrpc.php, ?feed=...).
* New: Exponential ban escalation (default 30 min → 6 h → 7 days); offense
  counter resets after 30 days of quiet.
* New: DB-backed ban log (`wp_sirl_log`) with admin viewer, IP filter,
  pagination, clear action, and daily auto-prune.
* New: `Reset offense counters` admin action.
* New: `sirl_ip_banned` action now receives the ban reason.

= 1.4.0 =
* Fix: IP spoofing via X-Forwarded-For / CF-Connecting-IP — headers are now
  trusted only from configured proxy IPs.
* Fix: atomic counters via wp_cache_incr when a persistent object cache is
  available; fixed-window bucketing replaces the sliding-TTL transient.
* Fix: `.htaccess` sync uses `insert_with_markers()` with flock for safe,
  atomic updates. Removes the permanent `.sirl.bak` leak.
* Fix: hook moved from `plugins_loaded` priority 0 to `init` so pluggable
  functions are guaranteed to be loaded.
* Fix: whitelist now validates entries on save and supports IPv4/IPv6 CIDR.
* Fix: `unban_ip()` also clears the per-IP counter.
* Fix: admin render no longer writes to the options table on every GET.
* Change: default excluded paths no longer include wp-login.php, xmlrpc.php,
  /admin-ajax.php, /wp-json/.
* Change: logged-in non-admin users are no longer exempt; only users with
  `manage_options` bypass the limiter (configurable).
* New: trusted proxies setting and Cloudflare toggle with bundled CF ranges.
* New: "Unban all" button and "synced" notice in the admin screen.

= 1.3.0 =
Added WP-Cron task (every 5 minutes) to purge expired bans and auto-sync
.htaccess.

= 1.2.0 =
Writes a managed .htaccess block to deny banned IPs at Apache level.

= 1.1.0 =
Added admin page to view active bans and unban IPs.

= 1.0.0 =
Initial release.
