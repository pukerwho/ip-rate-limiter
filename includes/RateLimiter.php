<?php
if (!defined('ABSPATH')) { exit; }

class SIRL_RateLimiter {
    private $settings;
    private $ip;
    private $ua;
    private $path;
    private $key_prefix = 'sirl_';
    const CACHE_GROUP            = 'sirl';
    const OFFENSE_RESET_SECONDS  = 30 * DAY_IN_SECONDS;
    const OFFENSE_PURGE_SECONDS  = 90 * DAY_IN_SECONDS;

    public function __construct($settings) {
        $this->settings = $settings;
        $this->ip       = $this->get_ip();
        $this->ua       = isset($_SERVER['HTTP_USER_AGENT']) ? (string) $_SERVER['HTTP_USER_AGENT'] : '';
        $this->path     = isset($_SERVER['REQUEST_URI'])
            ? (string) parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH)
            : '/';
    }

    public function handle() {
        if (!filter_var($this->ip, FILTER_VALIDATE_IP)) { return; }

        if (self::ip_in_list($this->ip, self::parse_list($this->settings['whitelist'] ?? ''))) {
            return;
        }

        if ($this->is_banned($this->ip)) {
            $this->deny();
        }

        if (!empty($this->settings['honeypot_enabled']) && $this->is_honeypot($this->path)) {
            $this->ban_with_reason('honeypot');
            $this->deny();
        }

        if (!empty($this->settings['ua_filter_enabled']) && $this->ua_is_blocked($this->ua)) {
            $this->ban_with_reason('ua_filter');
            $this->deny();
        }

        if ($this->is_excluded_path($this->path)) { return; }
        if (!empty($this->settings['ignore_static']) && $this->has_static_extension($this->path)) { return; }

        $strict = !empty($this->settings['strict_paths_enabled']) && $this->is_strict_path();
        if ($strict) {
            $limit  = max(1, intval($this->settings['strict_limit']));
            $window = max(1, intval($this->settings['strict_window']));
            $bucket = 'strict';
        } else {
            $limit  = max(1, intval($this->settings['limit']));
            $window = max(1, intval($this->settings['window']));
            $bucket = 'normal';
        }

        $count = $this->increment_counter($this->ip, $window, $bucket);
        if ($count > $limit) {
            $this->ban_with_reason($strict ? 'strict_limit' : 'rate_limit');
            $this->deny();
        }
    }

    public function get_client_ip() {
        return $this->ip;
    }

    /* ------------------------------ IP helpers ----------------------------- */

    private function get_ip() {
        $remote = isset($_SERVER['REMOTE_ADDR']) ? trim((string) $_SERVER['REMOTE_ADDR']) : '';
        if (!filter_var($remote, FILTER_VALIDATE_IP)) {
            return '0.0.0.0';
        }

        $trust_cf        = !empty($this->settings['trust_cloudflare']);
        $trusted_proxies = self::parse_list($this->settings['trusted_proxies'] ?? '');
        if ($trust_cf) {
            $trusted_proxies = array_merge($trusted_proxies, self::cloudflare_ranges());
        }

        if (empty($trusted_proxies) || !self::ip_in_list($remote, $trusted_proxies)) {
            return $remote;
        }

        $headers = array();
        if ($trust_cf) { $headers[] = 'HTTP_CF_CONNECTING_IP'; }
        $headers[] = 'HTTP_X_FORWARDED_FOR';
        $headers[] = 'HTTP_X_REAL_IP';

        foreach ($headers as $h) {
            if (empty($_SERVER[$h])) { continue; }
            $parts = explode(',', (string) $_SERVER[$h]);
            foreach ($parts as $p) {
                $candidate = trim($p);
                if (filter_var($candidate, FILTER_VALIDATE_IP)) {
                    return $candidate;
                }
            }
        }

        return $remote;
    }

    public static function parse_list($raw) {
        $items = preg_split('/[\s,]+/', (string) $raw);
        $items = array_filter(array_map('trim', (array) $items));
        return array_values($items);
    }

    public static function ip_in_list($ip, array $list) {
        foreach ($list as $entry) {
            if (self::ip_matches($ip, $entry)) { return true; }
        }
        return false;
    }

    public static function ip_matches($ip, $entry) {
        if ($ip === '' || $entry === '') { return false; }
        if (strpos($entry, '/') === false) {
            return filter_var($entry, FILTER_VALIDATE_IP) && inet_pton($ip) === inet_pton($entry);
        }
        list($subnet, $bits) = array_pad(explode('/', $entry, 2), 2, '');
        $bits   = (int) $bits;
        $ip_bin = @inet_pton($ip);
        $sn_bin = @inet_pton($subnet);
        if ($ip_bin === false || $sn_bin === false || strlen($ip_bin) !== strlen($sn_bin)) {
            return false;
        }
        $max_bits = strlen($ip_bin) * 8;
        if ($bits < 0 || $bits > $max_bits) { return false; }
        if ($bits === 0) { return true; }

        $full_bytes = intdiv($bits, 8);
        $rem_bits   = $bits % 8;

        if ($full_bytes > 0 && substr($ip_bin, 0, $full_bytes) !== substr($sn_bin, 0, $full_bytes)) {
            return false;
        }
        if ($rem_bits > 0) {
            $mask = (0xff << (8 - $rem_bits)) & 0xff;
            if ((ord($ip_bin[$full_bytes]) & $mask) !== (ord($sn_bin[$full_bytes]) & $mask)) {
                return false;
            }
        }
        return true;
    }

    public static function is_valid_ip_or_cidr($entry) {
        if (filter_var($entry, FILTER_VALIDATE_IP)) { return true; }
        if (strpos($entry, '/') === false) { return false; }
        list($subnet, $bits) = array_pad(explode('/', $entry, 2), 2, '');
        if (!filter_var($subnet, FILTER_VALIDATE_IP)) { return false; }
        if ($bits === '' || !ctype_digit((string) $bits)) { return false; }
        $bits = (int) $bits;
        $is_v6 = strpos($subnet, ':') !== false;
        $max   = $is_v6 ? 128 : 32;
        return $bits >= 0 && $bits <= $max;
    }

    public static function cloudflare_ranges() {
        return array(
            '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
            '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
            '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
            '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
            '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
            '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
        );
    }

    /* ------------------------------ Path / UA ------------------------------ */

    private function is_excluded_path($path) {
        $rows = preg_split('/[\r\n]+/', (string) ($this->settings['exclude_paths'] ?? ''));
        foreach ((array) $rows as $prefix) {
            $prefix = trim($prefix);
            if ($prefix === '' || $prefix === '/') { continue; }
            if (stripos($path, $prefix) === 0) { return true; }
        }
        return false;
    }

    private function has_static_extension($path) {
        $exts = (string) ($this->settings['static_extensions'] ?? '');
        $list = array_filter(array_map(function ($s) {
            $s = strtolower(trim($s));
            return $s === '' ? '' : '.' . ltrim($s, '.');
        }, explode(',', $exts)));
        $lower = strtolower($path);
        foreach ($list as $ext) {
            if ($ext !== '' && substr($lower, -strlen($ext)) === $ext) { return true; }
        }
        return false;
    }

    private function is_honeypot($path) {
        $hp = trim((string) ($this->settings['honeypot_path'] ?? ''));
        if ($hp === '' || $hp === '/') { return false; }
        return stripos($path, $hp) === 0;
    }

    private function is_strict_path() {
        $rows = preg_split('/[\r\n]+/', (string) ($this->settings['strict_paths'] ?? ''));
        foreach ((array) $rows as $prefix) {
            $prefix = trim($prefix);
            if ($prefix === '' || $prefix === '/') { continue; }
            if (stripos($this->path, $prefix) === 0) { return true; }
        }
        $qs = isset($_SERVER['REQUEST_URI'])
            ? (string) parse_url($_SERVER['REQUEST_URI'], PHP_URL_QUERY)
            : '';
        if ($qs !== '' && preg_match('~(^|&)feed=~i', $qs)) { return true; }
        return false;
    }

    private function ua_is_blocked($ua) {
        if ($ua === '') {
            return !empty($this->settings['ua_block_empty']);
        }
        $rows  = preg_split('/[\r\n]+/', (string) ($this->settings['ua_blocklist'] ?? ''));
        $lower = strtolower($ua);
        foreach ((array) $rows as $needle) {
            $needle = trim($needle);
            if ($needle === '' || strlen($needle) < 2) { continue; }
            if ($needle[0] === '~' && substr($needle, -1) === '~') {
                $pattern = '~' . substr($needle, 1, -1) . '~i';
                if (@preg_match($pattern, '') !== false && preg_match($pattern, $ua)) {
                    return true;
                }
                continue;
            }
            if (strpos($lower, strtolower($needle)) !== false) {
                return true;
            }
        }
        return false;
    }

    /* ------------------------------ Counters ------------------------------- */

    private function counter_key($ip, $window, $bucket_type) {
        $b = (int) floor(time() / max(1, $window));
        return $this->key_prefix . 'c_' . md5($ip) . '_' . $bucket_type . '_' . $window . '_' . $b;
    }
    private function ban_key($ip) {
        return $this->key_prefix . 'ban_' . md5($ip);
    }

    private function increment_counter($ip, $window, $bucket_type) {
        $key = $this->counter_key($ip, $window, $bucket_type);
        $ttl = $window + 1;

        if (function_exists('wp_using_ext_object_cache') && wp_using_ext_object_cache()) {
            $existing = wp_cache_get($key, self::CACHE_GROUP);
            if ($existing === false) {
                wp_cache_add($key, 0, self::CACHE_GROUP, $ttl);
            }
            $val = wp_cache_incr($key, 1, self::CACHE_GROUP);
            if ($val === false || $val === null) {
                wp_cache_set($key, 1, self::CACHE_GROUP, $ttl);
                return 1;
            }
            return (int) $val;
        }

        $data  = get_transient($key);
        $count = is_numeric($data) ? intval($data) + 1 : 1;
        set_transient($key, $count, $ttl);
        return $count;
    }

    private function is_banned($ip) {
        return (bool) get_transient($this->ban_key($ip));
    }

    /* -------------------------------- Ban ---------------------------------- */

    private function ban_with_reason($reason) {
        $ladder         = $this->escalation_ladder();
        $use_escalation = !empty($this->settings['escalation_enabled']);
        $offenses       = get_option('sirl_offenses', array());
        if (!is_array($offenses)) { $offenses = array(); }

        $now   = time();
        $entry = isset($offenses[$this->ip]) && is_array($offenses[$this->ip])
            ? $offenses[$this->ip]
            : array('count' => 0, 'last' => 0);

        if (!$use_escalation) {
            $entry['count'] = 1;
        } elseif (!empty($entry['last']) && ($now - intval($entry['last'])) > self::OFFENSE_RESET_SECONDS) {
            $entry['count'] = 1;
        } else {
            $entry['count'] = min(count($ladder), intval($entry['count']) + 1);
        }
        $entry['last']       = $now;
        $offenses[$this->ip] = $entry;
        update_option('sirl_offenses', $offenses, false);

        $idx     = min(count($ladder) - 1, max(0, intval($entry['count']) - 1));
        $minutes = max(1, intval($ladder[$idx]));
        $ttl     = $minutes * MINUTE_IN_SECONDS;
        $until   = $now + $ttl;

        set_transient(
            $this->ban_key($this->ip),
            array('ip' => $this->ip, 'until' => $until, 'reason' => $reason, 'offense' => $entry['count']),
            $ttl
        );

        $index = get_option('sirl_bans', array());
        if (!is_array($index)) { $index = array(); }
        $index[$this->ip] = $until;
        update_option('sirl_bans', $index, false);

        if (class_exists('SIRL_Logger') && !empty($this->settings['log_enabled'])) {
            SIRL_Logger::log(array(
                'ip'          => $this->ip,
                'ua'          => $this->ua,
                'path'        => $this->path,
                'reason'      => $reason,
                'offense'     => intval($entry['count']),
                'ban_minutes' => $minutes,
            ));
        }

        if (class_exists('SIRL_Htaccess')) {
            SIRL_Htaccess::sync(array_keys($index));
        }

        do_action('sirl_ip_banned', $this->ip, $until, $reason, $this->settings);
    }

    private function escalation_ladder() {
        $raw   = (string) ($this->settings['escalation_ladder'] ?? '30,360,10080');
        $items = array_values(array_filter(array_map('intval', explode(',', $raw)), function ($v) {
            return $v > 0;
        }));
        if (empty($items)) { $items = array(30, 360, 10080); }
        return $items;
    }

    public static function unban_ip($ip) {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) { return false; }
        delete_transient('sirl_ban_' . md5($ip));

        $index = get_option('sirl_bans', array());
        if (!is_array($index)) { $index = array(); }
        if (isset($index[$ip])) {
            unset($index[$ip]);
            update_option('sirl_bans', $index, false);
        }

        if (class_exists('SIRL_Htaccess')) {
            SIRL_Htaccess::sync(array_keys($index));
        }
        return true;
    }

    public static function reset_offenses($ip) {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) { return false; }
        $offenses = get_option('sirl_offenses', array());
        if (!is_array($offenses)) { return false; }
        if (isset($offenses[$ip])) {
            unset($offenses[$ip]);
            update_option('sirl_offenses', $offenses, false);
        }
        return true;
    }

    public static function purge_old_offenses() {
        $offenses = get_option('sirl_offenses', array());
        if (!is_array($offenses) || empty($offenses)) { return; }
        $now     = time();
        $cutoff  = $now - self::OFFENSE_PURGE_SECONDS;
        $changed = false;
        foreach ($offenses as $ip => $entry) {
            if (!is_array($entry) || empty($entry['last']) || intval($entry['last']) < $cutoff) {
                unset($offenses[$ip]);
                $changed = true;
            }
        }
        if ($changed) {
            update_option('sirl_offenses', $offenses, false);
        }
    }

    private function deny() {
        nocache_headers();
        if (!headers_sent()) {
            status_header(429);
            header('Retry-After: 60');
            header('Content-Type: text/plain; charset=utf-8');
            header('X-Robots-Tag: noindex, nofollow');
        }
        wp_die(
            esc_html__('Too Many Requests', 'simple-ip-rate-limiter'),
            esc_html__('Too Many Requests', 'simple-ip-rate-limiter'),
            array('response' => 429)
        );
    }
}
