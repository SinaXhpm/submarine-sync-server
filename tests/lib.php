<?php
// Shared helpers for the test suites. They run against a server you started
// for testing, and talk to its database directly to set things up and check
// them. THE SUITES EMPTY THAT DATABASE: never point them at a real server.
//
//   SUBMARINE_TEST_URL           the server, default http://127.0.0.1:18120
//   SUBMARINE_CONFIG_FILE        the config.php the server reads (the suites
//                                rewrite it to try other settings, and put it back)
//   SUBMARINE_TEST_DISPOSABLE=1  required: says the database may be emptied
//
// See tests/README.md.

declare(strict_types=1);

const ROOT = __DIR__ . '/..';
require ROOT . '/src/lib/Bootstrap.php';
\Submarine\Lib\Bootstrap::registerAutoload();

if (getenv('SUBMARINE_TEST_DISPOSABLE') !== '1') {
    fwrite(STDERR, "These tests empty the server's database. Set SUBMARINE_TEST_DISPOSABLE=1 to say that is fine.\n");
    exit(2);
}
define('BASE', rtrim((string) (getenv('SUBMARINE_TEST_URL') ?: 'http://127.0.0.1:18120'), '/'));
define('CFG_FILE', (string) getenv('SUBMARINE_CONFIG_FILE'));
if (CFG_FILE === '' || !is_file(CFG_FILE)) {
    fwrite(STDERR, "Set SUBMARINE_CONFIG_FILE to the config.php the test server reads.\n");
    exit(2);
}
define('CFG_ORIG', (string) file_get_contents(CFG_FILE));

$cfg = \Submarine\Lib\Config::load(ROOT);
$pdo = \Submarine\Lib\Bootstrap::connect($cfg);

$fails = 0;
function check(string $label, $got, $want): void
{
    global $fails;
    $ok = $got === $want;
    if (!$ok) $fails++;
    echo ($ok ? 'PASS ' : 'FAIL ') . $label . ': ' . json_encode($got, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)
        . ($ok ? '' : ' (expected ' . json_encode($want, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . ')') . "\n";
}
function done(): never
{
    global $fails;
    restoreConfig();
    echo $fails ? "$fails FAILED\n" : "ALL PASS\n";
    exit($fails ? 1 : 0);
}
function clearRL(): void
{
    global $pdo;
    $pdo->exec('DELETE FROM rate_limits');
}
function section(string $name): void
{
    clearRL();
    echo "---- $name\n";
}

/**
 * Run with other settings: the original config.php plus $over (merged), for
 * the server and for this process. restoreConfig() puts it back.
 */
function setConfig(array $over): void
{
    global $cfg;
    $base = require CFG_FILE . '.orig-for-tests';
    $merged = array_replace_recursive($base, $over);
    writeConfig("<?php\nreturn " . var_export($merged, true) . ";\n");
    $cfg = \Submarine\Lib\Config::load(ROOT);
}
function restoreConfig(): void
{
    global $cfg;
    writeConfig(CFG_ORIG);
    $cfg = \Submarine\Lib\Config::load(ROOT);
}
/**
 * Replace the config file in one step (a request never reads half of it).
 * The test server must run without opcache (php -d opcache.enable=0 -S ...),
 * or it keeps the old settings for a while.
 */
function writeConfig(string $text): void
{
    $tmp = CFG_FILE . '.tmp-' . bin2hex(random_bytes(4));
    file_put_contents($tmp, $text);
    chmod($tmp, 0600);
    rename($tmp, CFG_FILE);
    clearstatcache();
}
file_put_contents(CFG_FILE . '.orig-for-tests', CFG_ORIG);
chmod(CFG_FILE . '.orig-for-tests', 0600);
register_shutdown_function(static function (): void {
    if ((string) @file_get_contents(CFG_FILE) !== CFG_ORIG) {
        writeConfig(CFG_ORIG);
    }
});

/** One request. An array body goes as JSON; a string body as is, with $type. */
function req(string $method, string $path, $body = null, array $hdr = [], ?string $type = null): array
{
    $ch = curl_init(BASE . $path);
    $h  = [];
    foreach ($hdr as $k => $v) $h[] = "$k: $v";
    if (is_array($body)) {
        $body = json_encode($body);
        $type = $type ?? 'application/json';
    }
    if ($type !== null) $h[] = "Content-Type: $type";
    curl_setopt_array($ch, [
        CURLOPT_CUSTOMREQUEST  => $method,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER         => true,
        CURLOPT_HTTPHEADER     => $h,
        CURLOPT_TIMEOUT        => 120,
        CURLOPT_SSL_VERIFYPEER => getenv('SUBMARINE_TEST_INSECURE') !== '1',
        CURLOPT_SSL_VERIFYHOST => getenv('SUBMARINE_TEST_INSECURE') !== '1' ? 2 : 0,
    ]);
    if ($body !== null) curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
    $t0   = microtime(true);
    $resp = (string) curl_exec($ch);
    $hs   = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $text = substr($resp, $hs);
    return [
        'code'    => curl_getinfo($ch, CURLINFO_RESPONSE_CODE),
        'headers' => substr($resp, 0, $hs),
        'body'    => $text,
        'json'    => json_decode($text, true),
        'ms'      => (int) round((microtime(true) - $t0) * 1000),
    ];
}
function api(array $u, string $method, string $path, $body = null): array
{
    return req($method, $path, $body, ['X-Auth-Token' => $u['tok']]);
}
function header_of(array $r, string $name): ?string
{
    return preg_match('/^' . preg_quote($name, '/') . ':\s*(.+?)\r?$/mi', $r['headers'], $m) ? $m[1] : null;
}

/** The same request $n times at once; the status codes, sorted. */
function race(int $n, string $method, string $path, array $body): array
{
    $mh = curl_multi_init();
    $hs = [];
    for ($i = 0; $i < $n; $i++) {
        $ch = curl_init(BASE . $path);
        curl_setopt_array($ch, [
            CURLOPT_CUSTOMREQUEST  => $method,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
            CURLOPT_POSTFIELDS     => json_encode($body),
            CURLOPT_TIMEOUT        => 60,
        ]);
        curl_multi_add_handle($mh, $ch);
        $hs[] = $ch;
    }
    do {
        $st = curl_multi_exec($mh, $running);
        if ($running) curl_multi_select($mh, 1.0);
    } while ($running && $st === CURLM_OK);
    $codes = [];
    foreach ($hs as $ch) {
        $codes[] = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_multi_remove_handle($mh, $ch);
    }
    sort($codes);
    return $codes;
}

function stamp(int $ms, int $ctr = 0, string $node = 'a1b2c3d4e5f60718'): string
{
    return sprintf('%015d:%05d:%s', $ms, $ctr, $node);
}
function rec(string $etype, int $ms, ?string $blob = null, bool $deleted = false): array
{
    $r = ['uuid' => bin2hex(random_bytes(16)), 'entity_type' => $etype, 'updated_at' => stamp($ms), 'deleted' => $deleted];
    if (!$deleted || $blob !== null) $r['blob'] = $blob ?? bin2hex(random_bytes(40));
    return $r;
}
function rows(string $sql, array $args = []): array
{
    global $pdo;
    $st = $pdo->prepare($sql);
    $st->execute($args);
    return $st->fetchAll();
}
function one(string $sql, array $args = [])
{
    $r = rows($sql, $args);
    return $r ? array_values($r[0])[0] : null;
}

/** An active account with a password, signed in. */
function mkuser(string $email, string $pw = 'correct horse 1', array $hashOpts = []): array
{
    global $pdo;
    $hash = $hashOpts ? password_hash($pw, PASSWORD_BCRYPT, $hashOpts) : password_hash($pw, PASSWORD_DEFAULT);
    $pdo->prepare('INSERT INTO users (email, password_hash, status) VALUES (?, ?, "active")')->execute([$email, $hash]);
    $id = (int) $pdo->lastInsertId();
    clearRL();
    $r = req('POST', '/auth/login', ['email' => $email, 'password' => $pw]);
    return ['id' => $id, 'email' => $email, 'pw' => $pw, 'tok' => (string) ($r['json']['token'] ?? '')];
}
/** An account that signed up but hasn't set a password. */
function mkpending(string $email): int
{
    global $pdo;
    $pdo->prepare('INSERT INTO users (email, status) VALUES (?, "pending")')->execute([$email]);
    return (int) $pdo->lastInsertId();
}
/** A one-time code (verify / claim / reset / login) whose raw value we know. */
function mktoken(int $uid, string $purpose, int $ttl = 600): string
{
    global $pdo, $cfg;
    $raw = bin2hex(random_bytes(24));
    $pdo->prepare('INSERT INTO verify_tokens (token_hash, user_id, purpose, expires_at) VALUES (?, ?, ?, ?)')
        ->execute([hash_hmac('sha256', $raw, $cfg['security']['token_pepper']), $uid, $purpose, time() + $ttl]);
    return $raw;
}
/** Run bin/admin.php with the test settings; [exit code, output]. */
function cli(string ...$args): array
{
    $cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(ROOT . '/bin/admin.php');
    foreach ($args as $a) $cmd .= ' ' . escapeshellarg($a);
    $out = [];
    $rc = 0;
    exec($cmd . ' 2>&1', $out, $rc);
    return [$rc, implode("\n", $out)];
}
/** Wait for something written after the answer went out (mail, its audit row). */
function waitFor(callable $fn, float $seconds = 5.0)
{
    $until = microtime(true) + $seconds;
    do {
        $v = $fn();
        if ($v) return $v;
        usleep(100000);
    } while (microtime(true) < $until);
    return $v;
}
/** Start from an empty database. */
function wipe(): void
{
    global $pdo;
    foreach (['sync_records', 'sync_revs', 'sync_profiles', 'shared_records', 'shared_revs', 'profile_members', 'shared_profiles',
              'user_keys', 'deleted_shares', 'auth_events', 'auth_tokens', 'verify_tokens', 'rate_limits', 'admin_sessions', 'users'] as $t) {
        $pdo->exec("DELETE FROM `$t`");
    }
}
