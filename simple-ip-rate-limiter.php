<?php
/*
Plugin Name: Simple IP Rate Limiter
Description: Anti-scraping rate limiter. Blocks abusive IPs by request threshold, bad User-Agents, honeypot URL, or hits on sensitive endpoints (wp-json, feeds). Supports trusted proxies/Cloudflare, IPv4/IPv6 CIDR whitelist, exponential ban escalation, DB-backed ban log, atomic counters, safe .htaccess sync.
Version: 1.5.0
Author: Anna
License: GPLv2 or later
Text Domain: simple-ip-rate-limiter
*/

if (!defined('ABSPATH')) { exit; }

define('SIRL_VERSION', '1.5.0');
define('SIRL_OPTION_KEY', 'sirl_settings');
define('SIRL_PLUGIN_FILE', __FILE__);

require_once plugin_dir_path(__FILE__) . 'includes/RateLimiter.php';
require_once plugin_dir_path(__FILE__) . 'includes/Htaccess.php';
require_once plugin_dir_path(__FILE__) . 'includes/Logger.php';

class Simple_IP_Rate_Limiter {
    private static $instance = null;
    public $settings;

    public static function instance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    public static function defaults() {
        return array(
            'enabled'               => 1,
            'limit'                 => 120,
            'window'                => 10,
            'ban_minutes'           => 30,
            'whitelist'             => '',
            'trusted_proxies'       => '',
            'trust_cloudflare'      => 0,
            'bypass_admins'         => 1,
            'ignore_static'         => 1,
            'static_extensions'     => 'js,css,png,jpg,jpeg,gif,svg,webp,ico,woff,woff2,ttf,eot,pdf,zip,rar,7z,csv,txt,xml,map,mp3,mp4,m4a,mov,avi,mpeg,mpg,webm,ogg,wav',
            'exclude_paths'         => "/wp-admin/\n/wp-cron.php",

            // Strict limits for scraping-prone endpoints
            'strict_paths_enabled'  => 1,
            'strict_paths'          => "/wp-json/\n/feed\n/xmlrpc.php",
            'strict_limit'          => 15,
            'strict_window'         => 10,

            // User-Agent filter
            'ua_filter_enabled'     => 1,
            'ua_block_empty'        => 1,
            'ua_blocklist'          => implode("\n", array(
                'python-requests', 'python-urllib', 'aiohttp', 'httpx',
                'curl/', 'wget/', 'Go-http-client', 'okhttp', 'Java/', 'Apache-HttpClient',
                'scrapy', 'Scrapy', 'HeadlessChrome', 'PhantomJS', 'Puppeteer', 'Playwright',
                'node-fetch', 'got (', 'axios/', 'libwww-perl', 'Zeus ',
            )),

            // Honeypot
            'honeypot_enabled'      => 1,
            'honeypot_path'         => '/trap-bot',
            'honeypot_inject_link'  => 0,
            'honeypot_robots_txt'   => 0,

            // Escalation
            'escalation_enabled'    => 1,
            'escalation_ladder'     => '30,360,10080',

            // Logging
            'log_enabled'           => 1,
            'log_retention_days'    => 30,
        );
    }

    private function __construct() {
        $this->settings = wp_parse_args(get_option(SIRL_OPTION_KEY, array()), self::defaults());

        if (is_admin()) {
            require_once plugin_dir_path(__FILE__) . 'admin/settings.php';
            Simple_IP_Rate_Limiter_Admin::init($this);
            add_action('admin_init', array('SIRL_Logger', 'maybe_install'));
        }

        add_action('init',          array($this, 'maybe_block'),    0);
        add_action('wp_footer',     array($this, 'inject_honeypot_link'));
        add_filter('robots_txt',    array($this, 'filter_robots_txt'), 10, 2);
    }

    public function maybe_block() {
        if (empty($this->settings['enabled'])) { return; }

        if (!empty($this->settings['bypass_admins'])
            && function_exists('current_user_can')
            && current_user_can('manage_options')) {
            return;
        }

        if (defined('DOING_CRON') && DOING_CRON) { return; }
        if (defined('WP_CLI') && WP_CLI) { return; }

        $limiter = new SIRL_RateLimiter($this->settings);
        $limiter->handle();
    }

    public function inject_honeypot_link() {
        if (empty($this->settings['honeypot_enabled']))     { return; }
        if (empty($this->settings['honeypot_inject_link'])) { return; }
        $path = trim((string) $this->settings['honeypot_path']);
        if ($path === '' || $path[0] !== '/') { return; }

        printf(
            '<a href="%s" rel="nofollow noindex" aria-hidden="true" tabindex="-1" style="position:absolute;left:-10000px;top:auto;width:1px;height:1px;overflow:hidden">%s</a>',
            esc_url(home_url($path)),
            esc_html__('do-not-follow', 'simple-ip-rate-limiter')
        );
    }

    public function filter_robots_txt($output, $public) {
        if (empty($this->settings['honeypot_enabled']))  { return $output; }
        if (empty($this->settings['honeypot_robots_txt'])) { return $output; }
        $path = trim((string) $this->settings['honeypot_path']);
        if ($path === '' || $path[0] !== '/') { return $output; }
        return rtrim((string) $output) . "\nDisallow: " . $path . "\n";
    }
}

Simple_IP_Rate_Limiter::instance();

/* ------------------------------------------------------------------
 * Activation / deactivation.
 * ------------------------------------------------------------------ */

register_activation_hook(__FILE__, 'sirl_activate');
register_deactivation_hook(__FILE__, 'sirl_deactivate');

function sirl_activate() {
    SIRL_Logger::install();
    if (!wp_next_scheduled('sirl_cron_sync')) {
        wp_schedule_event(time() + 60, 'sirl_every_five_minutes', 'sirl_cron_sync');
    }
    if (!wp_next_scheduled('sirl_cron_daily')) {
        wp_schedule_event(time() + 120, 'daily', 'sirl_cron_daily');
    }
}

function sirl_deactivate() {
    foreach (array('sirl_cron_sync', 'sirl_cron_daily') as $hook) {
        $ts = wp_next_scheduled($hook);
        if ($ts) { wp_unschedule_event($ts, $hook); }
    }
    if (class_exists('SIRL_Htaccess')) { SIRL_Htaccess::remove(); }
}

/* ------------------------------------------------------------------
 * WP-Cron: every-5-min cleanup & daily prune.
 * ------------------------------------------------------------------ */

add_filter('cron_schedules', function ($s) {
    if (!isset($s['sirl_every_five_minutes'])) {
        $s['sirl_every_five_minutes'] = array(
            'interval' => 5 * MINUTE_IN_SECONDS,
            'display'  => 'Every 5 minutes (SIRL)',
        );
    }
    return $s;
});

add_action('wp_loaded', function () {
    if (!wp_next_scheduled('sirl_cron_sync')) {
        wp_schedule_event(time() + 60, 'sirl_every_five_minutes', 'sirl_cron_sync');
    }
    if (!wp_next_scheduled('sirl_cron_daily')) {
        wp_schedule_event(time() + 120, 'daily', 'sirl_cron_daily');
    }
});

add_action('sirl_cron_sync', function () {
    $bans = get_option('sirl_bans', array());
    if (!is_array($bans)) { $bans = array(); }
    $changed = false;
    $now     = time();
    foreach ($bans as $ip => $until) {
        if (!is_int($until) || $until <= $now) {
            unset($bans[$ip]);
            $changed = true;
        }
    }
    if ($changed) {
        update_option('sirl_bans', $bans, false);
    }
    if (class_exists('SIRL_Htaccess')) {
        SIRL_Htaccess::sync(array_keys($bans));
    }
});

add_action('sirl_cron_daily', function () {
    $settings = wp_parse_args(get_option(SIRL_OPTION_KEY, array()), Simple_IP_Rate_Limiter::defaults());
    if (class_exists('SIRL_Logger') && !empty($settings['log_enabled'])) {
        SIRL_Logger::prune(max(1, intval($settings['log_retention_days'])));
    }
    if (class_exists('SIRL_RateLimiter')) {
        SIRL_RateLimiter::purge_old_offenses();
    }
});
