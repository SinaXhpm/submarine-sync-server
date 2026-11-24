<?php
// Submarine sync server — settings.
//
// Three layers, each overriding the one before:
//   1. the defaults below,
//   2. config.php in the server's folder (copy config.example.php), if there is one,
//   3. environment variables (SUBMARINE_*), which is how Docker sets them.
//
// load() never prints a secret. problems() lists what is wrong in words an
// operator can act on; the server refuses to answer until the list is empty.

declare(strict_types=1);

namespace Submarine\Lib;

final class Config
{
    /** Routes of the API. The admin panel's address may not start with one. */
    public const API_PREFIXES = ['/auth', '/sync', '/keys', '/shares', '/health', '/api'];

    /** Headers a trusted proxy may name the client's address in. */
    public const CLIENT_IP_HEADERS = ['X-Forwarded-For', 'X-Real-IP', 'CF-Connecting-IP'];

    public static function defaults(): array
    {
        return [
            'db' => [
                'host'     => '127.0.0.1',
                'port'     => 3306,
                'name'     => 'submarine',
                'user'     => 'submarine',
                'password' => '',
                'charset'  => 'utf8mb4',
            ],
            // Who may make an account: 'invite' (the admin makes a code, no mail
            // needed) or 'open' (anyone, with a code sent by mail).
            'signup'       => 'invite',
            // Most accounts sign-up may make (0: no limit). Counts finished
            // accounts (active and suspended), not sign-ups nobody finished;
            // an admin's invitation is never held back by it.
            'max_accounts' => 0,
            // The server's address when it is not at the root of its host name,
            // for example '/submarine'. Empty at the root.
            'base_path'    => '',
            // How long a sign-in lasts on a device.
            'token_ttl_seconds' => 90 * 86400,
            'security' => [
                // Secret mixed into every stored token hash. 32+ random characters,
                // never changed afterwards (changing it signs everybody out).
                'token_pepper'     => '',
                // Reverse proxies in front of the server: IP addresses, CIDR ranges
                // or host names. Only a request from one of them may say who the
                // client is, in `client_ip_header`.
                'trusted_proxies'  => [],
                'client_ip_header' => 'X-Forwarded-For',
                // Setting up an account's sharing key the first time takes the
                // account password too. Released apps don't send it yet, so
                // this is off by default; see README, Security.
                'keys_need_password' => false,
            ],
            'mail' => [
                // 'off', 'smtp' or 'mail' (PHP's mail(), the host's own mail system).
                'transport'        => 'off',
                'from_address'     => '',
                'from_name'        => 'Submarine sync',
                'smtp_host'        => '',
                'smtp_port'        => 587,
                // 'starttls' (port 587), 'tls' (port 465) or 'none' (a relay on the
                // same machine or network only: the password goes unencrypted).
                'smtp_security'    => 'starttls',
                'smtp_user'        => '',
                'smtp_password'    => '',
                'smtp_verify_peer' => true,
                // Mails per hour for the whole server, so a flood of sign-up
                // requests can't make it send mail without end.
                'per_hour'         => 200,
            ],
            'admin' => [
                // A password hash (php bin/admin.php hash-password). Empty: no
                // admin panel. The command line (bin/admin.php) works either way.
                'password_hash' => '',
                'path'          => '/admin',
                // Let a browser on this machine open the panel over plain http
                // (http://localhost...). Off: the panel needs HTTPS.
                'allow_http_local' => false,
            ],
            // Storage per account and per shared profile.
            'quota' => [
                'bytes'         => 5 * 1024 * 1024,
                'records'       => 20000,
                'profiles'      => 100,
                'shares'        => 50,
                'share_bytes'   => 5 * 1024 * 1024,
                'share_records' => 20000,
            ],
            'limits' => [
                'max_json_bytes'           => 65536,
                'password_min_length'      => 8,
                // [requests, seconds]
                'rate_ip_global'           => [180, 60],
                'rate_ip_signup'           => [5, 3600],
                'rate_ip_login'            => [15, 300],
                'rate_ip_verify'           => [30, 3600],
                'rate_ip_request_reset'    => [5, 3600],
                'rate_ip_request_login'    => [10, 3600],
                'rate_email_signup'        => [3, 3600],
                'rate_email_login_attempt' => [10, 900],
                'rate_email_request_reset' => [3, 3600],
                'rate_email_request_login' => [5, 3600],
                'rate_user_global'         => [600, 60],
                'login_fail_threshold'     => 5,
                'lock_duration_seconds'    => 900,
                // Every failed sign-in is answered when the request is this old,
                // and every "check your inbox" answer at the second one, so the
                // time an answer takes doesn't tell whether an email has an
                // account. The first must be above one password check on this
                // machine (bin/admin.php check measures it).
                'login_fail_floor_ms'      => 1000,
                'account_mail_floor_ms'    => 400,
                // One-time codes.
                'verify_token_ttl'         => 86400,
                'invite_token_ttl'         => 7 * 86400,
                'claim_token_ttl'          => 600,
                'reset_token_ttl'          => 3600,
                'login_token_ttl'          => 900,
                // Clean-up (bin/cron.php).
                'pending_user_max_age'     => 7 * 86400,
                'audit_retain_seconds'     => 90 * 86400,
                // Failed requests that belong to no account (unknown tokens,
                // codes, emails) are kept a shorter time: anyone can make them.
                'audit_anon_retain_seconds'=> 7 * 86400,
                'rate_limit_retain_seconds'=> 7 * 86400,
            ],
        ];
    }

    /** The settings: defaults, then config.php, then the environment. */
    public static function load(string $root): array
    {
        $c = self::defaults();
        $file = (string) (getenv('SUBMARINE_CONFIG_FILE') ?: $root . '/config.php');
        if (is_file($file)) {
            $user = require $file;
            if (!is_array($user)) {
                throw new \RuntimeException('config.php must return an array');
            }
            $c = self::merge($c, $user);
            // A shared profile has the same caps as an account unless set apart.
            $uq = is_array($user['quota'] ?? null) ? $user['quota'] : [];
            if (isset($uq['bytes']) && !isset($uq['share_bytes'])) $c['quota']['share_bytes'] = $uq['bytes'];
            if (isset($uq['records']) && !isset($uq['share_records'])) $c['quota']['share_records'] = $uq['records'];
        }
        return self::fromEnv($c);
    }

    /** Nested merge: lists and plain values replace, maps merge key by key. */
    private static function merge(array $base, array $over): array
    {
        foreach ($over as $k => $v) {
            if (is_array($v) && isset($base[$k]) && is_array($base[$k]) && !array_is_list($v) && !array_is_list($base[$k])) {
                $base[$k] = self::merge($base[$k], $v);
            } else {
                $base[$k] = $v;
            }
        }
        return $base;
    }

    private static function env(string $name): ?string
    {
        $v = getenv($name);
        return ($v === false || $v === '') ? null : $v;
    }

    private static function fromEnv(array $c): array
    {
        $str = function (string $name, array &$slot, string $key): void {
            $v = self::env($name);
            if ($v !== null) $slot[$key] = $v;
        };
        $int = function (string $name, array &$slot, string $key): void {
            $v = self::env($name);
            if ($v !== null) $slot[$key] = filter_var($v, FILTER_VALIDATE_INT) === false ? $v : (int) $v;
        };
        $bool = function (string $name, array &$slot, string $key): void {
            $v = self::env($name);
            if ($v !== null) $slot[$key] = in_array(strtolower($v), ['1', 'true', 'yes', 'on'], true);
        };

        $str('SUBMARINE_DB_HOST', $c['db'], 'host');
        $int('SUBMARINE_DB_PORT', $c['db'], 'port');
        $str('SUBMARINE_DB_NAME', $c['db'], 'name');
        $str('SUBMARINE_DB_USER', $c['db'], 'user');
        $str('SUBMARINE_DB_PASSWORD', $c['db'], 'password');

        $str('SUBMARINE_SIGNUP', $c, 'signup');
        $int('SUBMARINE_MAX_ACCOUNTS', $c, 'max_accounts');
        $str('SUBMARINE_BASE_PATH', $c, 'base_path');
        $days = self::env('SUBMARINE_TOKEN_TTL_DAYS');
        if ($days !== null) {
            $c['token_ttl_seconds'] = ctype_digit($days) ? (int) $days * 86400 : $days;
        }

        $str('SUBMARINE_TOKEN_PEPPER', $c['security'], 'token_pepper');
        $list = self::env('SUBMARINE_TRUSTED_PROXIES');
        if ($list !== null) {
            $c['security']['trusted_proxies'] = array_values(array_filter(array_map('trim', explode(',', $list)), 'strlen'));
        }
        $str('SUBMARINE_CLIENT_IP_HEADER', $c['security'], 'client_ip_header');
        $bool('SUBMARINE_KEYS_NEED_PASSWORD', $c['security'], 'keys_need_password');

        $str('SUBMARINE_MAIL_TRANSPORT', $c['mail'], 'transport');
        $str('SUBMARINE_MAIL_FROM', $c['mail'], 'from_address');
        $str('SUBMARINE_MAIL_FROM_NAME', $c['mail'], 'from_name');
        $str('SUBMARINE_SMTP_HOST', $c['mail'], 'smtp_host');
        $int('SUBMARINE_SMTP_PORT', $c['mail'], 'smtp_port');
        $str('SUBMARINE_SMTP_SECURITY', $c['mail'], 'smtp_security');
        $str('SUBMARINE_SMTP_USER', $c['mail'], 'smtp_user');
        $str('SUBMARINE_SMTP_PASSWORD', $c['mail'], 'smtp_password');
        $bool('SUBMARINE_SMTP_VERIFY_PEER', $c['mail'], 'smtp_verify_peer');
        $int('SUBMARINE_MAIL_PER_HOUR', $c['mail'], 'per_hour');

        $str('SUBMARINE_ADMIN_PASSWORD_HASH', $c['admin'], 'password_hash');
        $str('SUBMARINE_ADMIN_PATH', $c['admin'], 'path');
        $bool('SUBMARINE_ADMIN_ALLOW_HTTP_LOCAL', $c['admin'], 'allow_http_local');

        $mb = self::env('SUBMARINE_QUOTA_MB');
        if ($mb !== null) {
            $bytes = ctype_digit($mb) ? (int) $mb * 1024 * 1024 : $mb;
            $c['quota']['bytes'] = $bytes;
            $c['quota']['share_bytes'] = $bytes;
        }
        $int('SUBMARINE_LOGIN_FLOOR_MS', $c['limits'], 'login_fail_floor_ms');
        $int('SUBMARINE_QUOTA_RECORDS', $c['quota'], 'records');
        $int('SUBMARINE_QUOTA_PROFILES', $c['quota'], 'profiles');
        $int('SUBMARINE_QUOTA_SHARES', $c['quota'], 'shares');
        $rec = self::env('SUBMARINE_QUOTA_RECORDS');
        if ($rec !== null && ctype_digit($rec)) {
            $c['quota']['share_records'] = (int) $rec;
        }

        // Normal forms.
        $c['signup'] = strtolower(trim((string) $c['signup']));
        $c['mail']['transport'] = strtolower(trim((string) $c['mail']['transport']));
        $c['mail']['smtp_security'] = strtolower(trim((string) $c['mail']['smtp_security']));
        $c['mail']['from_name'] = str_replace(["\r", "\n", "\0"], '', (string) $c['mail']['from_name']);
        $c['base_path'] = rtrim(trim((string) $c['base_path']), '/');
        $c['admin']['path'] = rtrim(trim((string) $c['admin']['path']), '/');
        return $c;
    }

    /** What is wrong with the settings, in plain words. Empty when all is well. */
    public static function problems(array $c): array
    {
        $p = [];
        $pepper = (string) ($c['security']['token_pepper'] ?? '');
        if (strlen($pepper) < 32 || stripos($pepper, 'change') !== false) {
            $p[] = 'SUBMARINE_TOKEN_PEPPER (security.token_pepper) must be a random secret of 32 or more characters, for example from: openssl rand -hex 32';
        }
        foreach (['host', 'name', 'user'] as $k) {
            if (trim((string) ($c['db'][$k] ?? '')) === '') {
                $p[] = "The database $k is not set (SUBMARINE_DB_" . strtoupper($k) . ').';
            }
        }
        if (!is_int($c['db']['port'] ?? null) || $c['db']['port'] < 1 || $c['db']['port'] > 65535) {
            $p[] = 'SUBMARINE_DB_PORT must be a port number.';
        }
        if (!in_array($c['signup'], ['invite', 'open'], true)) {
            $p[] = "SUBMARINE_SIGNUP must be 'invite' or 'open'.";
        }
        if (!is_int($c['max_accounts']) || $c['max_accounts'] < 0) {
            $p[] = 'SUBMARINE_MAX_ACCOUNTS must be 0 (no limit) or a positive number.';
        }
        if (!is_int($c['token_ttl_seconds']) || $c['token_ttl_seconds'] < 3600) {
            $p[] = 'SUBMARINE_TOKEN_TTL_DAYS must be a whole number of days, 1 or more.';
        }
        $bp = $c['base_path'];
        if ($bp !== '' && !preg_match('#^(/[A-Za-z0-9._~-]+)+$#', $bp)) {
            $p[] = "SUBMARINE_BASE_PATH must look like '/submarine' (letters, digits, - _ . ~), or be empty.";
        }

        foreach ((array) $c['security']['trusted_proxies'] as $t) {
            if (!self::validProxyEntry((string) $t)) {
                $p[] = "SUBMARINE_TRUSTED_PROXIES: '$t' is not an IP address, a CIDR range or a host name.";
            }
        }
        if (!in_array($c['security']['client_ip_header'], self::CLIENT_IP_HEADERS, true)) {
            $p[] = 'SUBMARINE_CLIENT_IP_HEADER must be one of: ' . implode(', ', self::CLIENT_IP_HEADERS) . '.';
        }

        $m = $c['mail'];
        if (!in_array($m['transport'], ['off', 'smtp', 'mail'], true)) {
            $p[] = "SUBMARINE_MAIL_TRANSPORT must be 'off', 'smtp' or 'mail'.";
        } elseif ($m['transport'] !== 'off') {
            if (!filter_var((string) $m['from_address'], FILTER_VALIDATE_EMAIL)) {
                $p[] = 'SUBMARINE_MAIL_FROM must be the email address mail is sent from.';
            }
            if ($m['transport'] === 'smtp') {
                if (!preg_match('/^[A-Za-z0-9.-]{1,253}$/', (string) $m['smtp_host'])) {
                    $p[] = 'SUBMARINE_SMTP_HOST must be the mail server\'s host name or address.';
                }
                if (!is_int($m['smtp_port']) || $m['smtp_port'] < 1 || $m['smtp_port'] > 65535) {
                    $p[] = 'SUBMARINE_SMTP_PORT must be a port number.';
                }
                if (!in_array($m['smtp_security'], ['starttls', 'tls', 'none'], true)) {
                    $p[] = "SUBMARINE_SMTP_SECURITY must be 'starttls', 'tls' or 'none'.";
                }
            }
        }
        // 0 or a word here would hold back every account mail without a sound.
        if ($m['transport'] !== 'off' && (!is_int($m['per_hour'] ?? null) || $m['per_hour'] < 1)) {
            $p[] = 'SUBMARINE_MAIL_PER_HOUR must be a whole number, 1 or more.';
        }
        if ($c['signup'] === 'open' && $m['transport'] === 'off') {
            $p[] = "SUBMARINE_SIGNUP=open needs mail (SUBMARINE_MAIL_TRANSPORT), or nobody gets their code. Use 'invite' without mail.";
        }

        $hash = (string) $c['admin']['password_hash'];
        if ($hash !== '' && (password_get_info($hash)['algo'] ?? null) === null) {
            $p[] = 'SUBMARINE_ADMIN_PASSWORD_HASH is not a password hash. Make one with: php bin/admin.php hash-password';
        }
        $ap = $c['admin']['path'];
        if (!preg_match('#^(/[A-Za-z0-9._~-]+)+$#', $ap)) {
            $p[] = "SUBMARINE_ADMIN_PATH must look like '/admin' (letters, digits, - _ . ~).";
        } else {
            foreach (self::API_PREFIXES as $pre) {
                if ($ap === $pre || str_starts_with($ap, $pre . '/')) {
                    $p[] = "SUBMARINE_ADMIN_PATH can't be under $pre: the API answers there.";
                }
            }
        }

        foreach (['login_fail_floor_ms', 'account_mail_floor_ms'] as $k) {
            $v = $c['limits'][$k] ?? null;
            if (!is_int($v) || $v < 100 || $v > 10000) {
                $p[] = "limits.$k must be a number of milliseconds between 100 and 10000.";
            }
        }
        // Each rate limit is [most requests, window in seconds] (config.php).
        foreach ($c['limits'] as $k => $v) {
            if (preg_match('/^rate_(ip|email|user)_/', (string) $k)
                && (!is_array($v) || array_keys($v) !== [0, 1] || !is_int($v[0]) || !is_int($v[1]) || $v[0] < 1 || $v[1] < 1)) {
                $p[] = "limits.$k must be [most requests, seconds], two whole numbers of 1 or more.";
            }
        }
        foreach (['bytes', 'records', 'profiles', 'shares', 'share_bytes', 'share_records'] as $k) {
            if (!is_int($c['quota'][$k] ?? null) || $c['quota'][$k] < 1) {
                $p[] = "quota.$k must be a positive whole number.";
            }
        }
        return $p;
    }

    /** An IP address, a CIDR range, or a host name. */
    public static function validProxyEntry(string $t): bool
    {
        if (filter_var($t, FILTER_VALIDATE_IP)) {
            return true;
        }
        if (str_contains($t, '/')) {
            [$net, $bits] = explode('/', $t, 2);
            if (!ctype_digit($bits) || !filter_var($net, FILTER_VALIDATE_IP)) {
                return false;
            }
            $max = str_contains($net, ':') ? 128 : 32;
            return (int) $bits <= $max;
        }
        return (bool) preg_match('/^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/', $t);
    }
}
