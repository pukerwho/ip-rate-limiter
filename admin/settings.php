<?php
if (!defined('ABSPATH')) { exit; }

class Simple_IP_Rate_Limiter_Admin {
    private static $plugin;

    public static function init($plugin_instance) {
        self::$plugin = $plugin_instance;
        add_action('admin_menu',                        array(__CLASS__, 'menu'));
        add_action('admin_init',                        array(__CLASS__, 'register'));
        add_action('admin_post_sirl_unban',             array(__CLASS__, 'handle_unban'));
        add_action('admin_post_sirl_unban_all',         array(__CLASS__, 'handle_unban_all'));
        add_action('admin_post_sirl_sync_htaccess',     array(__CLASS__, 'handle_sync_htaccess'));
        add_action('admin_post_sirl_clear_logs',        array(__CLASS__, 'handle_clear_logs'));
        add_action('admin_post_sirl_reset_offenses',    array(__CLASS__, 'handle_reset_offenses'));
    }

    public static function menu() {
        add_options_page(
            __('IP Rate Limiter', 'simple-ip-rate-limiter'),
            __('IP Rate Limiter', 'simple-ip-rate-limiter'),
            'manage_options',
            'sirl',
            array(__CLASS__, 'render')
        );
        add_options_page(
            __('IP Rate Limiter — Logs', 'simple-ip-rate-limiter'),
            __('IP Rate Limiter — Logs', 'simple-ip-rate-limiter'),
            'manage_options',
            'sirl-logs',
            array(__CLASS__, 'render_logs')
        );
    }

    public static function register() {
        register_setting('sirl_group', SIRL_OPTION_KEY, array(
            'type'              => 'array',
            'sanitize_callback' => array(__CLASS__, 'sanitize'),
            'default'           => Simple_IP_Rate_Limiter::defaults(),
        ));

        // --- Main ---
        add_settings_section('sirl_main', __('Rate-limit settings', 'simple-ip-rate-limiter'), function () {
            echo '<p>' . esc_html__('Tuned for anti-scraping. Lower "Max requests" and raise "Ban duration" to be stricter.', 'simple-ip-rate-limiter') . '</p>';
        }, 'sirl');
        add_settings_field('enabled',           __('Enable protection', 'simple-ip-rate-limiter'),         array(__CLASS__, 'field_enabled'),       'sirl', 'sirl_main');
        add_settings_field('limit',             __('Max requests (per window)', 'simple-ip-rate-limiter'), array(__CLASS__, 'field_limit'),         'sirl', 'sirl_main');
        add_settings_field('window',            __('Time window (seconds)', 'simple-ip-rate-limiter'),     array(__CLASS__, 'field_window'),        'sirl', 'sirl_main');
        add_settings_field('ban_minutes',       __('Base ban duration (minutes)', 'simple-ip-rate-limiter'), array(__CLASS__, 'field_ban'),         'sirl', 'sirl_main');
        add_settings_field('whitelist',         __('Whitelist IPs / CIDR', 'simple-ip-rate-limiter'),      array(__CLASS__, 'field_whitelist'),     'sirl', 'sirl_main');
        add_settings_field('ignore_static',     __('Ignore static assets', 'simple-ip-rate-limiter'),      array(__CLASS__, 'field_ignore_static'), 'sirl', 'sirl_main');
        add_settings_field('static_extensions', __('Static extensions', 'simple-ip-rate-limiter'),         array(__CLASS__, 'field_static_ext'),    'sirl', 'sirl_main');
        add_settings_field('exclude_paths',     __('Excluded paths', 'simple-ip-rate-limiter'),            array(__CLASS__, 'field_exclude_paths'), 'sirl', 'sirl_main');
        add_settings_field('bypass_admins',     __('Bypass for site admins', 'simple-ip-rate-limiter'),    array(__CLASS__, 'field_bypass_admins'), 'sirl', 'sirl_main');

        // --- Strict limits ---
        add_settings_section('sirl_strict', __('Strict limits for scraping-prone endpoints', 'simple-ip-rate-limiter'), function () {
            echo '<p>' . esc_html__('Apply a tighter counter for /wp-json/, feeds, xmlrpc — typical scraper targets.', 'simple-ip-rate-limiter') . '</p>';
        }, 'sirl');
        add_settings_field('strict_paths_enabled', __('Enable strict limits', 'simple-ip-rate-limiter'),   array(__CLASS__, 'field_strict_enabled'), 'sirl', 'sirl_strict');
        add_settings_field('strict_paths',         __('Strict paths', 'simple-ip-rate-limiter'),           array(__CLASS__, 'field_strict_paths'),   'sirl', 'sirl_strict');
        add_settings_field('strict_limit',         __('Strict max requests', 'simple-ip-rate-limiter'),    array(__CLASS__, 'field_strict_limit'),   'sirl', 'sirl_strict');
        add_settings_field('strict_window',        __('Strict time window (sec)', 'simple-ip-rate-limiter'), array(__CLASS__, 'field_strict_window'),'sirl', 'sirl_strict');

        // --- User-Agent ---
        add_settings_section('sirl_ua', __('User-Agent filter', 'simple-ip-rate-limiter'), function () {
            echo '<p>' . esc_html__('Match User-Agent against a blocklist. Matching requests trigger a ban (and escalation, if enabled). Use ~regex~ for regex entries.', 'simple-ip-rate-limiter') . '</p>';
        }, 'sirl');
        add_settings_field('ua_filter_enabled', __('Enable UA filter', 'simple-ip-rate-limiter'),    array(__CLASS__, 'field_ua_enabled'),   'sirl', 'sirl_ua');
        add_settings_field('ua_block_empty',    __('Block empty User-Agent', 'simple-ip-rate-limiter'), array(__CLASS__, 'field_ua_empty'), 'sirl', 'sirl_ua');
        add_settings_field('ua_blocklist',      __('UA blocklist', 'simple-ip-rate-limiter'),        array(__CLASS__, 'field_ua_list'),      'sirl', 'sirl_ua');

        // --- Honeypot ---
        add_settings_section('sirl_hp', __('Honeypot', 'simple-ip-rate-limiter'), function () {
            echo '<p>' . esc_html__('Any hit to the honeypot path triggers an instant ban. A hidden link can be auto-injected into the frontend footer so scrapers walking every link find it; real users never see it.', 'simple-ip-rate-limiter') . '</p>';
        }, 'sirl');
        add_settings_field('honeypot_enabled',     __('Enable honeypot', 'simple-ip-rate-limiter'),        array(__CLASS__, 'field_hp_enabled'), 'sirl', 'sirl_hp');
        add_settings_field('honeypot_path',        __('Honeypot path', 'simple-ip-rate-limiter'),          array(__CLASS__, 'field_hp_path'),    'sirl', 'sirl_hp');
        add_settings_field('honeypot_inject_link', __('Inject hidden link in footer', 'simple-ip-rate-limiter'), array(__CLASS__, 'field_hp_inject'), 'sirl', 'sirl_hp');
        add_settings_field('honeypot_robots_txt',  __('Advertise in robots.txt', 'simple-ip-rate-limiter'),array(__CLASS__, 'field_hp_robots'),  'sirl', 'sirl_hp');

        // --- Escalation ---
        add_settings_section('sirl_esc', __('Ban escalation', 'simple-ip-rate-limiter'), function () {
            echo '<p>' . esc_html__('Repeat offenders are banned for progressively longer durations. Offense count resets after 30 days of no ban.', 'simple-ip-rate-limiter') . '</p>';
        }, 'sirl');
        add_settings_field('escalation_enabled', __('Enable escalation', 'simple-ip-rate-limiter'), array(__CLASS__, 'field_esc_enabled'), 'sirl', 'sirl_esc');
        add_settings_field('escalation_ladder',  __('Ladder (minutes, comma-separated)', 'simple-ip-rate-limiter'), array(__CLASS__, 'field_esc_ladder'), 'sirl', 'sirl_esc');

        // --- Logging ---
        add_settings_section('sirl_log', __('Logging', 'simple-ip-rate-limiter'), function () {
            echo '<p>' . esc_html__('Each new ban is written to a dedicated table (wp_sirl_log) with IP, UA, path, reason and offense count.', 'simple-ip-rate-limiter') . '</p>';
        }, 'sirl');
        add_settings_field('log_enabled',        __('Enable logging', 'simple-ip-rate-limiter'),         array(__CLASS__, 'field_log_enabled'),   'sirl', 'sirl_log');
        add_settings_field('log_retention_days', __('Retention (days)', 'simple-ip-rate-limiter'),       array(__CLASS__, 'field_log_retention'), 'sirl', 'sirl_log');

        // --- Proxy / CDN ---
        add_settings_section('sirl_proxy', __('Proxy / CDN', 'simple-ip-rate-limiter'), function () {
            echo '<p>' . esc_html__('If your site is behind a reverse proxy or CDN, configure it below. Otherwise client IP header spoofing allows full bypass.', 'simple-ip-rate-limiter') . '</p>';
        }, 'sirl');
        add_settings_field('trust_cloudflare', __('Behind Cloudflare', 'simple-ip-rate-limiter'),          array(__CLASS__, 'field_trust_cf'),      'sirl', 'sirl_proxy');
        add_settings_field('trusted_proxies',  __('Trusted proxy IPs / CIDR', 'simple-ip-rate-limiter'),  array(__CLASS__, 'field_trusted_proxy'), 'sirl', 'sirl_proxy');
    }

    /* --------------------------- Sanitization --------------------------- */

    public static function sanitize($input) {
        $defaults = Simple_IP_Rate_Limiter::defaults();
        $out = array();

        foreach (array('enabled', 'ignore_static', 'trust_cloudflare', 'bypass_admins',
                       'strict_paths_enabled', 'ua_filter_enabled', 'ua_block_empty',
                       'honeypot_enabled', 'honeypot_inject_link', 'honeypot_robots_txt',
                       'escalation_enabled', 'log_enabled') as $flag) {
            $out[$flag] = empty($input[$flag]) ? 0 : 1;
        }

        $out['limit']              = max(1, intval($input['limit']              ?? $defaults['limit']));
        $out['window']             = max(1, intval($input['window']             ?? $defaults['window']));
        $out['ban_minutes']        = max(1, intval($input['ban_minutes']        ?? $defaults['ban_minutes']));
        $out['strict_limit']       = max(1, intval($input['strict_limit']       ?? $defaults['strict_limit']));
        $out['strict_window']      = max(1, intval($input['strict_window']      ?? $defaults['strict_window']));
        $out['log_retention_days'] = max(1, intval($input['log_retention_days'] ?? $defaults['log_retention_days']));

        $out['whitelist']       = self::sanitize_ip_list($input['whitelist']       ?? '');
        $out['trusted_proxies'] = self::sanitize_ip_list($input['trusted_proxies'] ?? '');

        $out['static_extensions'] = sanitize_text_field($input['static_extensions'] ?? $defaults['static_extensions']);
        $out['exclude_paths']     = self::sanitize_paths($input['exclude_paths']     ?? $defaults['exclude_paths']);
        $out['strict_paths']      = self::sanitize_paths($input['strict_paths']      ?? $defaults['strict_paths']);

        $out['ua_blocklist']      = self::sanitize_lines($input['ua_blocklist']      ?? $defaults['ua_blocklist']);

        $out['honeypot_path']     = self::sanitize_single_path($input['honeypot_path'] ?? $defaults['honeypot_path'], $defaults['honeypot_path']);

        $out['escalation_ladder'] = self::sanitize_ladder($input['escalation_ladder'] ?? $defaults['escalation_ladder']);

        return $out;
    }

    private static function sanitize_ip_list($raw) {
        $items = preg_split('/[\s,]+/', (string) $raw);
        $good  = array();
        $bad   = array();
        foreach ((array) $items as $item) {
            $item = trim($item);
            if ($item === '') { continue; }
            if (class_exists('SIRL_RateLimiter') && SIRL_RateLimiter::is_valid_ip_or_cidr($item)) {
                $good[$item] = true;
            } else {
                $bad[] = $item;
            }
        }
        if (!empty($bad)) {
            add_settings_error(
                SIRL_OPTION_KEY,
                'sirl_invalid_ip',
                sprintf(
                    /* translators: %s: list of invalid IPs */
                    esc_html__('Ignored invalid IP/CIDR entries: %s', 'simple-ip-rate-limiter'),
                    esc_html(implode(', ', $bad))
                ),
                'warning'
            );
        }
        return implode("\n", array_keys($good));
    }

    private static function sanitize_paths($raw) {
        $rows = preg_split('/[\r\n]+/', (string) $raw);
        $out  = array();
        foreach ((array) $rows as $row) {
            $row = trim($row);
            if ($row === '') { continue; }
            if ($row[0] !== '/') { $row = '/' . $row; }
            $out[$row] = true;
        }
        return implode("\n", array_keys($out));
    }

    private static function sanitize_single_path($raw, $fallback) {
        $row = trim((string) $raw);
        if ($row === '') { return $fallback; }
        if ($row[0] !== '/') { $row = '/' . $row; }
        return $row;
    }

    private static function sanitize_lines($raw) {
        $rows = preg_split('/[\r\n]+/', (string) $raw);
        $out  = array();
        foreach ((array) $rows as $row) {
            $row = trim(sanitize_text_field($row));
            if ($row !== '') { $out[$row] = true; }
        }
        return implode("\n", array_keys($out));
    }

    private static function sanitize_ladder($raw) {
        $items = array_values(array_filter(array_map('intval', explode(',', (string) $raw)), function ($v) {
            return $v > 0;
        }));
        if (empty($items)) { $items = array(30, 360, 10080); }
        return implode(',', $items);
    }

    /* ------------------------------ Render ------------------------------ */

    public static function render() {
        if (!current_user_can('manage_options')) { return; }

        $bans    = self::purge_expired_bans();
        $now     = time();
        $unbanned = isset($_GET['unbanned']) ? sanitize_text_field(wp_unslash($_GET['unbanned'])) : '';
        $synced   = !empty($_GET['synced']);
        $cleared  = !empty($_GET['cleared']);
        $offreset = !empty($_GET['offreset']);

        $can_write = class_exists('SIRL_Htaccess') && SIRL_Htaccess::can_write();

        $sync_url          = wp_nonce_url(admin_url('admin-post.php?action=sirl_sync_htaccess'), 'sirl_sync_htaccess');
        $unban_all_url     = wp_nonce_url(admin_url('admin-post.php?action=sirl_unban_all'),     'sirl_unban_all');
        $reset_offenses_url= wp_nonce_url(admin_url('admin-post.php?action=sirl_reset_offenses'),'sirl_reset_offenses');

        $object_cache = function_exists('wp_using_ext_object_cache') && wp_using_ext_object_cache();
        ?>
        <div class="wrap">
            <h1><?php esc_html_e('Simple IP Rate Limiter', 'simple-ip-rate-limiter'); ?></h1>
            <p>
                <a class="button" href="<?php echo esc_url(admin_url('options-general.php?page=sirl-logs')); ?>">
                    <?php esc_html_e('View ban logs', 'simple-ip-rate-limiter'); ?>
                </a>
            </p>

            <?php settings_errors(SIRL_OPTION_KEY); ?>
            <?php if ($synced): ?>
                <div class="notice notice-success is-dismissible"><p><?php esc_html_e('.htaccess synced.', 'simple-ip-rate-limiter'); ?></p></div>
            <?php endif; ?>
            <?php if ($cleared): ?>
                <div class="notice notice-success is-dismissible"><p><?php esc_html_e('All bans cleared.', 'simple-ip-rate-limiter'); ?></p></div>
            <?php endif; ?>
            <?php if ($offreset): ?>
                <div class="notice notice-success is-dismissible"><p><?php esc_html_e('Offense counters reset.', 'simple-ip-rate-limiter'); ?></p></div>
            <?php endif; ?>
            <?php if ($unbanned !== ''): ?>
                <div class="notice notice-success is-dismissible">
                    <p><?php echo esc_html(sprintf(__('IP %s unbanned.', 'simple-ip-rate-limiter'), $unbanned)); ?></p>
                </div>
            <?php endif; ?>

            <?php if (!$object_cache): ?>
                <div class="notice notice-warning">
                    <p><?php esc_html_e('No persistent object cache detected. Rate counters will be stored in the options table, which is slow under heavy load. Install Redis/Memcached object cache for atomic counters.', 'simple-ip-rate-limiter'); ?></p>
                </div>
            <?php endif; ?>

            <form method="post" action="options.php">
                <?php settings_fields('sirl_group'); ?>
                <?php do_settings_sections('sirl'); ?>
                <?php submit_button(); ?>
            </form>

            <hr style="margin:2em 0" />

            <h2><?php esc_html_e('Banned IPs (active)', 'simple-ip-rate-limiter'); ?></h2>

            <table class="widefat striped" style="max-width:900px;">
                <thead>
                    <tr>
                        <th><?php esc_html_e('IP Address', 'simple-ip-rate-limiter'); ?></th>
                        <th><?php esc_html_e('Time remaining', 'simple-ip-rate-limiter'); ?></th>
                        <th><?php esc_html_e('Actions', 'simple-ip-rate-limiter'); ?></th>
                    </tr>
                </thead>
                <tbody>
                <?php if (empty($bans)): ?>
                    <tr><td colspan="3"><?php esc_html_e('No active bans.', 'simple-ip-rate-limiter'); ?></td></tr>
                <?php else: ?>
                    <?php foreach ($bans as $ip => $until):
                        $remain = max(0, $until - $now);
                        $h = (int) floor($remain / 3600);
                        $m = (int) floor(($remain % 3600) / 60);
                        $s = $remain % 60;
                        $label = ($h > 0 ? $h . 'h ' : '') . ($m > 0 ? $m . 'm ' : '') . $s . 's';
                        $nonce = wp_create_nonce('sirl_unban_' . $ip);
                    ?>
                    <tr>
                        <td><code><?php echo esc_html($ip); ?></code></td>
                        <td><?php echo esc_html($label); ?></td>
                        <td>
                            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="display:inline">
                                <input type="hidden" name="action"   value="sirl_unban">
                                <input type="hidden" name="ip"       value="<?php echo esc_attr($ip); ?>">
                                <input type="hidden" name="_wpnonce" value="<?php echo esc_attr($nonce); ?>">
                                <?php submit_button(__('Unban', 'simple-ip-rate-limiter'), 'delete small', '', false); ?>
                            </form>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
                </tbody>
            </table>

            <p style="margin-top:1em;">
                <?php if (!empty($bans)): ?>
                    <a class="button" href="<?php echo esc_url($unban_all_url); ?>" onclick="return confirm('<?php echo esc_js(__('Unban all IPs?', 'simple-ip-rate-limiter')); ?>')">
                        <?php esc_html_e('Unban all', 'simple-ip-rate-limiter'); ?>
                    </a>
                <?php endif; ?>

                <a class="button" href="<?php echo esc_url($reset_offenses_url); ?>" onclick="return confirm('<?php echo esc_js(__('Reset offense counters for all IPs? Next ban will be at level 1.', 'simple-ip-rate-limiter')); ?>')">
                    <?php esc_html_e('Reset all offense counters', 'simple-ip-rate-limiter'); ?>
                </a>

                <?php if ($can_write): ?>
                    <a class="button" href="<?php echo esc_url($sync_url); ?>">
                        <?php esc_html_e('Force sync .htaccess now', 'simple-ip-rate-limiter'); ?>
                    </a>
                <?php else: ?>
                    <span class="notice notice-warning" style="padding:8px;display:inline-block;">
                        <?php esc_html_e('Warning: .htaccess is not writable. Apache-level bans will not apply.', 'simple-ip-rate-limiter'); ?>
                    </span>
                <?php endif; ?>
            </p>
        </div>
        <?php
    }

    public static function render_logs() {
        if (!current_user_can('manage_options')) { return; }
        if (class_exists('SIRL_Logger')) { SIRL_Logger::maybe_install(); }

        $ip_filter = isset($_GET['filter_ip']) ? sanitize_text_field(wp_unslash($_GET['filter_ip'])) : '';
        $paged     = max(1, isset($_GET['paged']) ? intval($_GET['paged']) : 1);
        $per_page  = 50;
        $offset    = ($paged - 1) * $per_page;

        $total   = class_exists('SIRL_Logger') ? SIRL_Logger::count_all($ip_filter) : 0;
        $entries = class_exists('SIRL_Logger') ? SIRL_Logger::recent($per_page, $offset, $ip_filter) : array();
        $pages   = max(1, (int) ceil($total / $per_page));

        $clear_url = wp_nonce_url(admin_url('admin-post.php?action=sirl_clear_logs'), 'sirl_clear_logs');
        ?>
        <div class="wrap">
            <h1><?php esc_html_e('IP Rate Limiter — Ban Log', 'simple-ip-rate-limiter'); ?></h1>
            <p>
                <a class="button" href="<?php echo esc_url(admin_url('options-general.php?page=sirl')); ?>">
                    <?php esc_html_e('← Back to settings', 'simple-ip-rate-limiter'); ?>
                </a>
                <a class="button delete" href="<?php echo esc_url($clear_url); ?>" onclick="return confirm('<?php echo esc_js(__('Delete ALL log entries?', 'simple-ip-rate-limiter')); ?>')">
                    <?php esc_html_e('Clear log', 'simple-ip-rate-limiter'); ?>
                </a>
            </p>

            <?php if (!empty($_GET['log_cleared'])): ?>
                <div class="notice notice-success is-dismissible"><p><?php esc_html_e('Log cleared.', 'simple-ip-rate-limiter'); ?></p></div>
            <?php endif; ?>

            <form method="get" style="margin:1em 0;">
                <input type="hidden" name="page" value="sirl-logs">
                <label>
                    <?php esc_html_e('Filter by IP:', 'simple-ip-rate-limiter'); ?>
                    <input type="text" name="filter_ip" value="<?php echo esc_attr($ip_filter); ?>" placeholder="1.2.3.4">
                </label>
                <?php submit_button(__('Filter', 'simple-ip-rate-limiter'), 'secondary', '', false); ?>
                <?php if ($ip_filter !== ''): ?>
                    <a class="button" href="<?php echo esc_url(admin_url('options-general.php?page=sirl-logs')); ?>"><?php esc_html_e('Reset', 'simple-ip-rate-limiter'); ?></a>
                <?php endif; ?>
            </form>

            <p><?php echo esc_html(sprintf(__('Total: %d', 'simple-ip-rate-limiter'), $total)); ?></p>

            <table class="widefat striped">
                <thead>
                    <tr>
                        <th><?php esc_html_e('Time (UTC)', 'simple-ip-rate-limiter'); ?></th>
                        <th><?php esc_html_e('IP', 'simple-ip-rate-limiter'); ?></th>
                        <th><?php esc_html_e('Reason', 'simple-ip-rate-limiter'); ?></th>
                        <th><?php esc_html_e('Offense', 'simple-ip-rate-limiter'); ?></th>
                        <th><?php esc_html_e('Ban (min)', 'simple-ip-rate-limiter'); ?></th>
                        <th><?php esc_html_e('Path', 'simple-ip-rate-limiter'); ?></th>
                        <th><?php esc_html_e('User-Agent', 'simple-ip-rate-limiter'); ?></th>
                    </tr>
                </thead>
                <tbody>
                <?php if (empty($entries)): ?>
                    <tr><td colspan="7"><?php esc_html_e('No entries.', 'simple-ip-rate-limiter'); ?></td></tr>
                <?php else: foreach ($entries as $e): ?>
                    <tr>
                        <td><code><?php echo esc_html($e->created_at); ?></code></td>
                        <td>
                            <code><?php echo esc_html($e->ip); ?></code><br>
                            <small><a href="<?php echo esc_url(admin_url('options-general.php?page=sirl-logs&filter_ip=' . rawurlencode($e->ip))); ?>"><?php esc_html_e('filter', 'simple-ip-rate-limiter'); ?></a></small>
                        </td>
                        <td><?php echo esc_html($e->reason); ?></td>
                        <td><?php echo esc_html($e->offense); ?></td>
                        <td><?php echo esc_html($e->ban_minutes); ?></td>
                        <td><code style="word-break:break-all;"><?php echo esc_html($e->path); ?></code></td>
                        <td><small><?php echo esc_html($e->ua); ?></small></td>
                    </tr>
                <?php endforeach; endif; ?>
                </tbody>
            </table>

            <?php if ($pages > 1): ?>
                <div class="tablenav"><div class="tablenav-pages">
                    <?php
                    $base_url = add_query_arg(array(
                        'page'      => 'sirl-logs',
                        'filter_ip' => $ip_filter,
                    ), admin_url('options-general.php'));
                    echo paginate_links(array(
                        'base'      => add_query_arg('paged', '%#%', $base_url),
                        'format'    => '',
                        'total'     => $pages,
                        'current'   => $paged,
                        'prev_text' => '‹',
                        'next_text' => '›',
                    ));
                    ?>
                </div></div>
            <?php endif; ?>
        </div>
        <?php
    }

    private static function purge_expired_bans() {
        $bans = get_option('sirl_bans', array());
        if (!is_array($bans)) { $bans = array(); }
        $now = time();
        $changed = false;
        foreach ($bans as $ip => $until) {
            if (!is_int($until) || $until <= $now) {
                unset($bans[$ip]);
                $changed = true;
            }
        }
        if ($changed) {
            update_option('sirl_bans', $bans, false);
        }
        return $bans;
    }

    /* ------------------------------ Actions ------------------------------ */

    public static function handle_unban() {
        if (!current_user_can('manage_options')) { wp_die(esc_html__('Forbidden', 'simple-ip-rate-limiter')); }
        $ip = isset($_POST['ip']) ? sanitize_text_field(wp_unslash($_POST['ip'])) : '';
        if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) {
            wp_die(esc_html__('Invalid IP', 'simple-ip-rate-limiter'));
        }
        check_admin_referer('sirl_unban_' . $ip);
        if (class_exists('SIRL_RateLimiter')) {
            SIRL_RateLimiter::unban_ip($ip);
        }
        wp_safe_redirect(admin_url('options-general.php?page=sirl&unbanned=' . rawurlencode($ip)));
        exit;
    }

    public static function handle_unban_all() {
        if (!current_user_can('manage_options')) { wp_die(esc_html__('Forbidden', 'simple-ip-rate-limiter')); }
        check_admin_referer('sirl_unban_all');
        $bans = get_option('sirl_bans', array());
        if (is_array($bans)) {
            foreach (array_keys($bans) as $ip) {
                if (class_exists('SIRL_RateLimiter')) {
                    SIRL_RateLimiter::unban_ip($ip);
                }
            }
        }
        update_option('sirl_bans', array(), false);
        if (class_exists('SIRL_Htaccess')) { SIRL_Htaccess::sync(array()); }
        wp_safe_redirect(admin_url('options-general.php?page=sirl&cleared=1'));
        exit;
    }

    public static function handle_sync_htaccess() {
        if (!current_user_can('manage_options')) { wp_die(esc_html__('Forbidden', 'simple-ip-rate-limiter')); }
        check_admin_referer('sirl_sync_htaccess');
        $index = get_option('sirl_bans', array());
        if (!is_array($index)) { $index = array(); }
        if (class_exists('SIRL_Htaccess')) { SIRL_Htaccess::sync(array_keys($index)); }
        wp_safe_redirect(admin_url('options-general.php?page=sirl&synced=1'));
        exit;
    }

    public static function handle_clear_logs() {
        if (!current_user_can('manage_options')) { wp_die(esc_html__('Forbidden', 'simple-ip-rate-limiter')); }
        check_admin_referer('sirl_clear_logs');
        if (class_exists('SIRL_Logger')) { SIRL_Logger::clear(); }
        wp_safe_redirect(admin_url('options-general.php?page=sirl-logs&log_cleared=1'));
        exit;
    }

    public static function handle_reset_offenses() {
        if (!current_user_can('manage_options')) { wp_die(esc_html__('Forbidden', 'simple-ip-rate-limiter')); }
        check_admin_referer('sirl_reset_offenses');
        update_option('sirl_offenses', array(), false);
        wp_safe_redirect(admin_url('options-general.php?page=sirl&offreset=1'));
        exit;
    }

    /* ------------------------------- Fields ------------------------------ */

    private static function s($k) { return self::$plugin->settings[$k] ?? ''; }

    private static function checkbox($name, $label) {
        printf(
            '<label><input type="checkbox" name="%1$s[%2$s]" value="1" %3$s> %4$s</label>',
            esc_attr(SIRL_OPTION_KEY),
            esc_attr($name),
            checked(1, intval(self::s($name)), false),
            esc_html($label)
        );
    }

    private static function number_input($name, $extra = '') {
        printf(
            '<input type="number" min="1" name="%1$s[%2$s]" value="%3$s" class="small-text">%4$s',
            esc_attr(SIRL_OPTION_KEY),
            esc_attr($name),
            esc_attr(intval(self::s($name))),
            $extra ? ' <span class="description">' . esc_html($extra) . '</span>' : ''
        );
    }

    private static function text_input($name, $size = 60) {
        printf(
            '<input type="text" name="%1$s[%2$s]" value="%3$s" size="%4$d">',
            esc_attr(SIRL_OPTION_KEY),
            esc_attr($name),
            esc_attr(self::s($name)),
            intval($size)
        );
    }

    private static function textarea($name, $rows = 4, $cols = 60, $placeholder = '', $hint = '') {
        printf(
            '<textarea name="%1$s[%2$s]" rows="%3$d" cols="%4$d" placeholder="%5$s">%6$s</textarea>',
            esc_attr(SIRL_OPTION_KEY),
            esc_attr($name),
            intval($rows),
            intval($cols),
            esc_attr($placeholder),
            esc_textarea(self::s($name))
        );
        if ($hint !== '') {
            echo '<p class="description">' . esc_html($hint) . '</p>';
        }
    }

    // Main
    public static function field_enabled()       { self::checkbox('enabled', __('Enable', 'simple-ip-rate-limiter')); }
    public static function field_limit()         { self::number_input('limit', __('requests in the time window below', 'simple-ip-rate-limiter')); }
    public static function field_window()        { self::number_input('window', __('fixed window, in seconds', 'simple-ip-rate-limiter')); }
    public static function field_ban()           { self::number_input('ban_minutes', __('level-1 ban duration (escalation uses the ladder below)', 'simple-ip-rate-limiter')); }
    public static function field_whitelist()     { self::textarea('whitelist', 4, 60, "1.2.3.4\n5.6.7.0/24\n2001:db8::/32", __('One IP or CIDR per line. IPv4 and IPv6 supported.', 'simple-ip-rate-limiter')); }
    public static function field_ignore_static() { self::checkbox('ignore_static', __('Ignore common static file extensions', 'simple-ip-rate-limiter')); }
    public static function field_static_ext()    { self::text_input('static_extensions', 80); }
    public static function field_exclude_paths() { self::textarea('exclude_paths', 5, 80, "/wp-admin/\n/wp-cron.php", __('Prefix match. Keep wp-login.php, xmlrpc.php, /wp-json/ OUT of this list — those are scraping/brute-force targets.', 'simple-ip-rate-limiter')); }
    public static function field_bypass_admins() { self::checkbox('bypass_admins', __('Skip rate limiting for users with manage_options', 'simple-ip-rate-limiter')); }

    // Strict
    public static function field_strict_enabled(){ self::checkbox('strict_paths_enabled', __('Apply stricter limits to the paths below', 'simple-ip-rate-limiter')); }
    public static function field_strict_paths()  { self::textarea('strict_paths', 4, 60, "/wp-json/\n/feed\n/xmlrpc.php", __('Prefix match. Feed query (?feed=...) is always treated as strict automatically.', 'simple-ip-rate-limiter')); }
    public static function field_strict_limit()  { self::number_input('strict_limit'); }
    public static function field_strict_window() { self::number_input('strict_window'); }

    // UA
    public static function field_ua_enabled()    { self::checkbox('ua_filter_enabled', __('Ban requests matching the blocklist', 'simple-ip-rate-limiter')); }
    public static function field_ua_empty()      { self::checkbox('ua_block_empty', __('Ban requests with empty User-Agent header', 'simple-ip-rate-limiter')); }
    public static function field_ua_list()       { self::textarea('ua_blocklist', 10, 60, "python-requests\ncurl/\nGo-http-client\n~Headless(Chrome|Firefox)~", __('One entry per line. Substring match (case-insensitive). Wrap a pattern in ~tildes~ to treat it as a regex.', 'simple-ip-rate-limiter')); }

    // Honeypot
    public static function field_hp_enabled()    { self::checkbox('honeypot_enabled', __('Any hit to the honeypot path = instant ban', 'simple-ip-rate-limiter')); }
    public static function field_hp_path()       { self::text_input('honeypot_path', 40); echo ' <span class="description">' . esc_html__('Path prefix, e.g. /trap-bot', 'simple-ip-rate-limiter') . '</span>'; }
    public static function field_hp_inject()     { self::checkbox('honeypot_inject_link', __('Inject invisible link in frontend footer (scrapers that walk every link will hit it)', 'simple-ip-rate-limiter')); }
    public static function field_hp_robots()     { self::checkbox('honeypot_robots_txt', __('Add Disallow entry to robots.txt (warns legit crawlers, tempts bad ones)', 'simple-ip-rate-limiter')); }

    // Escalation
    public static function field_esc_enabled()   { self::checkbox('escalation_enabled', __('Apply progressively longer bans to repeat offenders', 'simple-ip-rate-limiter')); }
    public static function field_esc_ladder()    { self::text_input('escalation_ladder', 40); echo ' <span class="description">' . esc_html__('Minutes. E.g. 30,360,10080 = 30 min → 6 h → 7 days.', 'simple-ip-rate-limiter') . '</span>'; }

    // Log
    public static function field_log_enabled()   { self::checkbox('log_enabled', __('Write bans to wp_sirl_log', 'simple-ip-rate-limiter')); }
    public static function field_log_retention() { self::number_input('log_retention_days', __('days before old entries are pruned', 'simple-ip-rate-limiter')); }

    // Proxy
    public static function field_trust_cf()      {
        self::checkbox('trust_cloudflare', __('Trust CF-Connecting-IP when request comes from Cloudflare ranges', 'simple-ip-rate-limiter'));
        echo '<p class="description">' . esc_html__('Only enable if your origin is actually fronted by Cloudflare.', 'simple-ip-rate-limiter') . '</p>';
    }
    public static function field_trusted_proxy() {
        self::textarea('trusted_proxies', 3, 60, "10.0.0.0/8\n192.168.0.0/16", __('Additional reverse-proxy IPs/CIDRs. X-Forwarded-For / X-Real-IP are trusted only when REMOTE_ADDR matches.', 'simple-ip-rate-limiter'));
    }
}
