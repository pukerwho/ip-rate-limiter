<?php
if (!defined('ABSPATH')) { exit; }

class SIRL_Htaccess {
    const MARKER = 'SIRL-RATE-LIMITER';

    public static function htaccess_path() {
        return trailingslashit(ABSPATH) . '.htaccess';
    }

    public static function can_write() {
        $path = self::htaccess_path();
        if (file_exists($path)) { return is_writable($path); }
        return is_writable(dirname($path));
    }

    public static function generate_lines(array $ips) {
        $ips = array_values(array_unique(array_filter(array_map('trim', $ips), 'strlen')));
        $valid = array();
        foreach ($ips as $ip) {
            if (class_exists('SIRL_RateLimiter') && SIRL_RateLimiter::is_valid_ip_or_cidr($ip)) {
                $valid[] = $ip;
            } elseif (filter_var($ip, FILTER_VALIDATE_IP)) {
                $valid[] = $ip;
            }
        }

        $out = array();
        $out[] = '# Managed by Simple IP Rate Limiter. Do not edit manually.';
        $out[] = '<IfModule mod_authz_core.c>';
        $out[] = '  <RequireAll>';
        $out[] = '    Require all granted';
        foreach ($valid as $ip) {
            $out[] = '    Require not ip ' . $ip;
        }
        $out[] = '  </RequireAll>';
        $out[] = '</IfModule>';
        $out[] = '<IfModule !mod_authz_core.c>';
        $out[] = '  Order allow,deny';
        $out[] = '  Allow from all';
        foreach ($valid as $ip) {
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                $out[] = '  Deny from ' . $ip;
            }
        }
        $out[] = '</IfModule>';
        return $out;
    }

    public static function sync(array $ips) {
        $path = self::htaccess_path();

        if (!self::can_write()) { return false; }

        if (!function_exists('insert_with_markers')) {
            require_once ABSPATH . 'wp-admin/includes/misc.php';
        }

        // insert_with_markers() already uses flock(LOCK_EX) internally,
        // so we MUST NOT wrap it in our own flock — that deadlocks on Linux
        // because flock is per-inode and the nested call on a second fd
        // blocks waiting for the outer lock to release.
        return (bool) insert_with_markers($path, self::MARKER, self::generate_lines($ips));
    }

    public static function remove() {
        $path = self::htaccess_path();
        if (!file_exists($path) || !is_writable($path)) { return false; }

        if (!function_exists('insert_with_markers')) {
            require_once ABSPATH . 'wp-admin/includes/misc.php';
        }
        return (bool) insert_with_markers($path, self::MARKER, array());
    }
}
