<?php
// Every setting the README's table lists reaches the settings (Config), and
// docker-compose.yml passes every one of them to the app. No server needed.
//   php tests/config-test.php
declare(strict_types=1);

require __DIR__ . '/../src/lib/Bootstrap.php';
\Submarine\Lib\Bootstrap::registerAutoload();

use Submarine\Lib\Config;

$fails = 0;
function check(string $label, $got, $want): void
{
    global $fails;
    $ok = $got === $want;
    if (!$ok) $fails++;
    echo ($ok ? 'PASS ' : 'FAIL ') . $label . ': ' . json_encode($got, JSON_UNESCAPED_SLASHES)
        . ($ok ? '' : ' (expected ' . json_encode($want, JSON_UNESCAPED_SLASHES) . ')') . "\n";
}

// The names in the README's settings table ("`SUBMARINE_SMTP_HOST`, `_PORT`").
$readme = (string) file_get_contents(__DIR__ . '/../README.md');
$names = [];
foreach (explode("\n", $readme) as $line) {
    if (!str_starts_with($line, '| `SUBMARINE_')) continue;
    $cell = explode('|', $line)[1];
    preg_match_all('/`([A-Z_]+)`/', $cell, $m);
    $first = $m[1][0];
    foreach ($m[1] as $n) {
        $names[] = str_starts_with($n, 'SUBMARINE_') ? $n : preg_replace('/_[A-Z]+$/', '', $first) . $n;
    }
}
check('the README lists settings', count($names) > 20, true);

// A value for each, and where it must land.
$cases = [
    'SUBMARINE_DB_HOST' => ['db.example', ['db', 'host'], 'db.example'],
    'SUBMARINE_DB_PORT' => ['3307', ['db', 'port'], 3307],
    'SUBMARINE_DB_NAME' => ['n1', ['db', 'name'], 'n1'],
    'SUBMARINE_DB_USER' => ['u1', ['db', 'user'], 'u1'],
    'SUBMARINE_DB_PASSWORD' => ['p1', ['db', 'password'], 'p1'],
    'SUBMARINE_TOKEN_PEPPER' => [str_repeat('ab', 20), ['security', 'token_pepper'], str_repeat('ab', 20)],
    'SUBMARINE_SIGNUP' => ['open', ['signup'], 'open'],
    'SUBMARINE_MAX_ACCOUNTS' => ['12', ['max_accounts'], 12],
    'SUBMARINE_BASE_PATH' => ['/sub/', ['base_path'], '/sub'],
    'SUBMARINE_TRUSTED_PROXIES' => ['10.0.0.1, caddy', ['security', 'trusted_proxies'], ['10.0.0.1', 'caddy']],
    'SUBMARINE_CLIENT_IP_HEADER' => ['X-Real-IP', ['security', 'client_ip_header'], 'X-Real-IP'],
    'SUBMARINE_KEYS_NEED_PASSWORD' => ['1', ['security', 'keys_need_password'], true],
    'SUBMARINE_MAIL_TRANSPORT' => ['smtp', ['mail', 'transport'], 'smtp'],
    'SUBMARINE_MAIL_FROM' => ['a@b.example', ['mail', 'from_address'], 'a@b.example'],
    'SUBMARINE_MAIL_FROM_NAME' => ["Name\r\nX: y", ['mail', 'from_name'], 'NameX: y'],
    'SUBMARINE_SMTP_HOST' => ['smtp.example', ['mail', 'smtp_host'], 'smtp.example'],
    'SUBMARINE_SMTP_PORT' => ['465', ['mail', 'smtp_port'], 465],
    'SUBMARINE_SMTP_SECURITY' => ['TLS', ['mail', 'smtp_security'], 'tls'],
    'SUBMARINE_SMTP_USER' => ['user', ['mail', 'smtp_user'], 'user'],
    'SUBMARINE_SMTP_PASSWORD' => ['secret', ['mail', 'smtp_password'], 'secret'],
    'SUBMARINE_SMTP_VERIFY_PEER' => ['false', ['mail', 'smtp_verify_peer'], false],
    'SUBMARINE_MAIL_PER_HOUR' => ['55', ['mail', 'per_hour'], 55],
    'SUBMARINE_ADMIN_PASSWORD_HASH' => ['$2y$10$abc', ['admin', 'password_hash'], '$2y$10$abc'],
    'SUBMARINE_ADMIN_PATH' => ['/manage/', ['admin', 'path'], '/manage'],
    'SUBMARINE_ADMIN_ALLOW_HTTP_LOCAL' => ['yes', ['admin', 'allow_http_local'], true],
    'SUBMARINE_QUOTA_MB' => ['7', ['quota', 'bytes'], 7 * 1024 * 1024],
    'SUBMARINE_QUOTA_RECORDS' => ['300', ['quota', 'records'], 300],
    'SUBMARINE_QUOTA_PROFILES' => ['9', ['quota', 'profiles'], 9],
    'SUBMARINE_QUOTA_SHARES' => ['4', ['quota', 'shares'], 4],
    'SUBMARINE_TOKEN_TTL_DAYS' => ['30', ['token_ttl_seconds'], 30 * 86400],
    'SUBMARINE_LOGIN_FLOOR_MS' => ['1500', ['limits', 'login_fail_floor_ms'], 1500],
];
putenv('SUBMARINE_CONFIG_FILE=' . __DIR__ . '/no-such-config.php');
$compose = (string) file_get_contents(__DIR__ . '/../docker-compose.yml');
$env = (string) file_get_contents(__DIR__ . '/../.env.example');
foreach (array_unique($names) as $name) {
    if (!isset($cases[$name])) {
        check("$name has a case in this test", false, true);
        continue;
    }
    [$value, $path, $want] = $cases[$name];
    putenv("$name=$value");
    $got = Config::load(__DIR__ . '/..');
    putenv($name);
    foreach ($path as $k) $got = $got[$k] ?? null;
    check("$name reaches " . implode('.', $path), $got, $want);
    check("$name is passed by docker-compose.yml", (bool) preg_match('/^\s+' . $name . ':/m', $compose), true);
}
// Two that follow others.
putenv('SUBMARINE_QUOTA_MB=3');
putenv('SUBMARINE_QUOTA_RECORDS=111');
$c = Config::load(__DIR__ . '/..');
putenv('SUBMARINE_QUOTA_MB');
putenv('SUBMARINE_QUOTA_RECORDS');
check('a shared profile follows the account quotas', [$c['quota']['share_bytes'], $c['quota']['share_records']], [3 * 1024 * 1024, 111]);
// Empty values (what compose passes for a setting left blank) keep the default.
putenv('SUBMARINE_TOKEN_TTL_DAYS=');
putenv('SUBMARINE_SMTP_VERIFY_PEER=');
$c = Config::load(__DIR__ . '/..');
check('an empty value keeps the default', [$c['token_ttl_seconds'], $c['mail']['smtp_verify_peer']], [90 * 86400, true]);
foreach (['SUBMARINE_DB_PASSWORD', 'SUBMARINE_TOKEN_PEPPER', 'SUBMARINE_SIGNUP', 'SUBMARINE_ADMIN_ALLOW_HTTP_LOCAL', 'SUBMARINE_KEYS_NEED_PASSWORD'] as $n) {
    check(".env.example mentions $n", str_contains($env, "$n="), true);
}

// problems(): a mail cap of 0 and a broken rate pair are named, not silently used.
putenv('SUBMARINE_TOKEN_PEPPER=' . str_repeat('cd', 20));
putenv('SUBMARINE_MAIL_TRANSPORT=smtp');
putenv('SUBMARINE_MAIL_FROM=a@b.example');
putenv('SUBMARINE_SMTP_HOST=smtp.example');
$c = Config::load(__DIR__ . '/..');
check('the base settings have no problems', Config::problems($c), []);
$has = fn (array $c, string $needle): bool => (bool) array_filter(Config::problems($c), fn ($s) => str_contains($s, $needle));
foreach ([0, -3, '5'] as $bad) {
    $x = $c;
    $x['mail']['per_hour'] = $bad;
    check('mail per_hour ' . json_encode($bad) . ' is a problem', $has($x, 'SUBMARINE_MAIL_PER_HOUR'), true);
}
$x = $c;
$x['mail']['per_hour'] = 0;
$x['mail']['transport'] = 'off';
check('with mail off, per_hour does not matter', $has($x, 'SUBMARINE_MAIL_PER_HOUR'), false);
foreach ([[0, 60], [5], [5, '60'], ['a' => 5, 'b' => 60], 5, [5, 0]] as $bad) {
    $x = $c;
    $x['limits']['rate_ip_login'] = $bad;
    check('rate pair ' . json_encode($bad) . ' is a problem', $has($x, 'limits.rate_ip_login'), true);
}
foreach (['SUBMARINE_TOKEN_PEPPER', 'SUBMARINE_MAIL_TRANSPORT', 'SUBMARINE_MAIL_FROM', 'SUBMARINE_SMTP_HOST'] as $n) putenv($n);

echo $fails ? "$fails FAILED\n" : "ALL PASS\n";
exit($fails ? 1 : 0);
