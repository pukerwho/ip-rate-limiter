<?php
if (!defined('ABSPATH')) { exit; }

class SIRL_Logger {
    const TABLE            = 'sirl_log';
    const OPT_DB_VERSION   = 'sirl_db_version';
    const CURRENT_DB_VER   = '1';

    public static function table_name() {
        global $wpdb;
        return $wpdb->prefix . self::TABLE;
    }

    public static function install() {
        global $wpdb;
        $table   = self::table_name();
        $charset = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE {$table} (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            ip VARCHAR(45) NOT NULL DEFAULT '',
            ua VARCHAR(500) NOT NULL DEFAULT '',
            path VARCHAR(500) NOT NULL DEFAULT '',
            reason VARCHAR(32) NOT NULL DEFAULT '',
            offense TINYINT UNSIGNED NOT NULL DEFAULT 1,
            ban_minutes INT UNSIGNED NOT NULL DEFAULT 0,
            created_at DATETIME NOT NULL,
            PRIMARY KEY  (id),
            KEY ip (ip),
            KEY created_at (created_at)
        ) {$charset};";

        if (!function_exists('dbDelta')) {
            require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        }
        dbDelta($sql);
        update_option(self::OPT_DB_VERSION, self::CURRENT_DB_VER, false);
    }

    public static function maybe_install() {
        if (get_option(self::OPT_DB_VERSION) !== self::CURRENT_DB_VER) {
            self::install();
        }
    }

    public static function uninstall() {
        global $wpdb;
        $table = self::table_name();
        $wpdb->query("DROP TABLE IF EXISTS {$table}");
        delete_option(self::OPT_DB_VERSION);
    }

    public static function log(array $row) {
        global $wpdb;
        $defaults = array(
            'ip'          => '',
            'ua'          => '',
            'path'        => '',
            'reason'      => '',
            'offense'     => 1,
            'ban_minutes' => 0,
            'created_at'  => current_time('mysql', true),
        );
        $row            = wp_parse_args($row, $defaults);
        $row['ip']      = substr((string) $row['ip'], 0, 45);
        $row['ua']      = self::truncate((string) $row['ua'], 500);
        $row['path']    = self::truncate((string) $row['path'], 500);
        $row['reason']  = substr((string) $row['reason'], 0, 32);
        $row['offense'] = max(1, intval($row['offense']));
        $row['ban_minutes'] = max(0, intval($row['ban_minutes']));

        $wpdb->insert(
            self::table_name(),
            $row,
            array('%s', '%s', '%s', '%s', '%d', '%d', '%s')
        );
    }

    private static function truncate($s, $max) {
        if (function_exists('mb_substr')) {
            return mb_substr($s, 0, $max);
        }
        return substr($s, 0, $max);
    }

    public static function prune($retention_days) {
        global $wpdb;
        $retention_days = max(1, intval($retention_days));
        $table   = self::table_name();
        $cutoff  = gmdate('Y-m-d H:i:s', time() - $retention_days * DAY_IN_SECONDS);
        $wpdb->query(
            $wpdb->prepare("DELETE FROM {$table} WHERE created_at < %s", $cutoff)
        );
    }

    public static function recent($limit = 100, $offset = 0, $ip = '') {
        global $wpdb;
        $table  = self::table_name();
        $limit  = max(1, min(500, intval($limit)));
        $offset = max(0, intval($offset));

        if ($ip !== '') {
            return $wpdb->get_results(
                $wpdb->prepare(
                    "SELECT * FROM {$table} WHERE ip = %s ORDER BY id DESC LIMIT %d OFFSET %d",
                    $ip, $limit, $offset
                )
            );
        }
        return $wpdb->get_results(
            $wpdb->prepare(
                "SELECT * FROM {$table} ORDER BY id DESC LIMIT %d OFFSET %d",
                $limit, $offset
            )
        );
    }

    public static function count_all($ip = '') {
        global $wpdb;
        $table = self::table_name();
        if ($ip !== '') {
            return (int) $wpdb->get_var(
                $wpdb->prepare("SELECT COUNT(*) FROM {$table} WHERE ip = %s", $ip)
            );
        }
        return (int) $wpdb->get_var("SELECT COUNT(*) FROM {$table}");
    }

    public static function clear() {
        global $wpdb;
        $table = self::table_name();
        $wpdb->query("TRUNCATE TABLE {$table}");
    }
}
