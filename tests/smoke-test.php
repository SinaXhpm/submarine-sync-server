<?php
// A quick round trip against a running server, over HTTP only, as the app
// does it: invitation, sign-up, sync both ways (plain, delta, gzipped),
// sharing between two accounts, sign-out, and account deletion. It makes its
// own accounts with random emails and deletes them at the end, so it is safe
// on a server with real accounts too.
//
//   SUBMARINE_TEST_URL=https://sync.example.com \
//   SUBMARINE_TEST_ADMIN_CMD="docker compose exec -T app php bin/admin.php" \
//   php tests/smoke-test.php
//
// SUBMARINE_TEST_ADMIN_CMD runs bin/admin.php wherever the server is (default:
// php bin/admin.php in this folder). SUBMARINE_TEST_INSECURE=1 accepts a
// certificate curl can't check (a test Caddy with its own CA).
declare(strict_types=1);

$base = rtrim((string) (getenv('SUBMARINE_TEST_URL') ?: 'http://127.0.0.1:8080'), '/');
$adminCmd = (string) (getenv('SUBMARINE_TEST_ADMIN_CMD') ?: escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/../bin/admin.php'));
$insecure = getenv('SUBMARINE_TEST_INSECURE') === '1';
$fails = 0;

function check(string $label, $got, $want): void
{
    global $fails;
    $ok = $got === $want;
    if (!$ok) $fails++;
    echo ($ok ? 'PASS ' : 'FAIL ') . $label . ': ' . json_encode($got, JSON_UNESCAPED_SLASHES)
        . ($ok ? '' : ' (expected ' . json_encode($want, JSON_UNESCAPED_SLASHES) . ')') . "\n";
}
function req(string $method, string $path, $body = null, array $hdr = [], bool $gzip = false): array
{
    global $base, $insecure;
    $ch = curl_init($base . $path);
    $h = [];
    foreach ($hdr as $k => $v) $h[] = "$k: $v";
    if (is_array($body)) {
        $body = json_encode($body);
        $h[] = 'Content-Type: application/json';
        if ($gzip) {
            $body = gzencode($body);
            $h[] = 'Content-Encoding: gzip';
            $h[] = 'Accept-Encoding: gzip';
        }
    }
    curl_setopt_array($ch, [
        CURLOPT_CUSTOMREQUEST => $method, CURLOPT_RETURNTRANSFER => true, CURLOPT_HEADER => true,
        CURLOPT_HTTPHEADER => $h, CURLOPT_TIMEOUT => 60,
        CURLOPT_SSL_VERIFYPEER => !$insecure, CURLOPT_SSL_VERIFYHOST => $insecure ? 0 : 2,
    ]);
    if ($body !== null) curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
    $resp = (string) curl_exec($ch);
    $hs = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $text = substr($resp, $hs);
    $head = substr($resp, 0, $hs);
    if (preg_match('/^content-encoding:\s*gzip/mi', $head)) $text = (string) gzdecode($text);
    return ['code' => curl_getinfo($ch, CURLINFO_RESPONSE_CODE), 'head' => $head, 'json' => json_decode($text, true), 'body' => $text];
}
function api(array $u, string $method, string $path, $body = null, bool $gzip = false): array
{
    return req($method, $path, $body, ['X-Auth-Token' => $u['tok']], $gzip);
}
function admin(string ...$args): string
{
    global $adminCmd;
    $cmd = $adminCmd;
    foreach ($args as $a) $cmd .= ' ' . escapeshellarg($a);
    return (string) shell_exec($cmd . ' 2>&1');
}
function rec(int $ms, bool $deleted = false): array
{
    $r = ['uuid' => bin2hex(random_bytes(16)), 'entity_type' => 'servers', 'updated_at' => sprintf('%015d:%05d:%s', $ms, 0, 'a1b2c3d4e5f60718'), 'deleted' => $deleted];
    if (!$deleted) $r['blob'] = bin2hex(random_bytes(64));
    return $r;
}
/** A new account through an invitation, as a person would make it in the app. */
function account(string $email, string $pw): array
{
    $out = admin('invite', $email);
    preg_match('/^\s{4}([0-9a-f]{48})\s*$/m', $out, $m);
    $v = req('GET', '/auth/verify?token=' . ($m[1] ?? 'none'));
    $s = req('POST', '/auth/set-password', ['claim_token' => $v['json']['claim_token'] ?? '', 'password' => $pw]);
    return ['email' => $email, 'pw' => $pw, 'tok' => (string) ($s['json']['token'] ?? ''), 'verify' => $v['code'], 'set' => $s['code']];
}

$now = (int) (microtime(true) * 1000);
$tag = bin2hex(random_bytes(4));
$r = req('GET', '/health');
check('health', [$r['code'], $r['json']['ok'] ?? null], [200, true]);
check('no X-Powered-By', (bool) preg_match('/^x-powered-by:/mi', $r['head']), false);
$r = req('POST', '/auth/signup', ['email' => "smoke-$tag@example.com"]);
check('sign-up is by invitation', [$r['code'], $r['json']['error'] ?? null], [403, 'signup_closed']);

$a = account("smoke-a-$tag@example.com", 'smoke password A1');
$b = account("smoke-b-$tag@example.com", 'smoke password B1');
check('invite, verify, choose a password: signed in', [$a['verify'], $a['set'], strlen($a['tok'])], [200, 200, 64]);
check('a second account', strlen($b['tok']), 64);
$r = req('POST', '/auth/login', ['email' => $a['email'], 'password' => $a['pw']]);
check('sign in with the password', [$r['code'], strlen((string) ($r['json']['token'] ?? ''))], [200, 64]);
$a2 = ['tok' => (string) $r['json']['token']];

$P = bin2hex(random_bytes(16));
$recs = [rec($now), rec($now + 1), rec($now + 2)];
$r = api($a, 'POST', '/sync', ['profile' => $P, 'name' => 'Smoke', 'since' => '', 'records' => $recs]);
check('push 3 records', [$r['code'], count($r['json']['records'] ?? []), is_int($r['json']['rev'] ?? null)], [200, 3, true]);
$rev = $r['json']['rev'] ?? 0;
$epoch = $r['json']['epoch'] ?? '';
$r = api($a2, 'POST', '/sync', ['profile' => $P, 'since' => '', 'records' => [rec($now + 3)]], true);
check('a second device pushes, gzipped', [$r['code'], count($r['json']['records'] ?? [])], [200, 4]);
$r = api($a, 'POST', '/sync', ['profile' => $P, 'since' => '', 'since_rev' => $rev, 'epoch' => $epoch, 'records' => []]);
check('the first device gets only the change (delta)', [$r['code'], count($r['json']['records'] ?? []), $r['json']['full'] ?? null], [200, 1, null]);
$r = api($a, 'GET', '/sync/profiles');
check('the profile list', [$r['code'], $r['json']['profiles'][0]['name'] ?? null, $r['json']['profiles'][0]['live_records'] ?? null], [200, 'Smoke', 4]);

$key = fn () => ['public_key' => bin2hex(random_bytes(32)), 'wrapped_privkey' => bin2hex(random_bytes(48)), 'enc_salt' => bin2hex(random_bytes(16))];
check('publish sharing keys', [api($a, 'POST', '/keys/publish', $key())['code'], api($b, 'POST', '/keys/publish', $key())['code']], [200, 200]);
$S = bin2hex(random_bytes(16));
check('share a profile', api($a, 'POST', '/shares/create', ['share_id' => $S, 'name' => 'Team', 'sealed_dek' => bin2hex(random_bytes(48))])['code'], 200);
check('invite the other account', api($a, 'POST', '/shares/invite', ['share_id' => $S, 'email' => $b['email'], 'role' => 'editor', 'sealed_dek' => bin2hex(random_bytes(48))])['code'], 200);
check('it accepts', api($b, 'POST', '/shares/accept', ['share_id' => $S])['code'], 200);
api($a, 'POST', '/shares/sync', ['share_id' => $S, 'since' => '', 'records' => [rec($now + 10)]]);
$r = api($b, 'POST', '/shares/sync', ['share_id' => $S, 'since' => '', 'records' => [rec($now + 11)]], true);
check('both sync the shared profile', [$r['code'], count($r['json']['records'] ?? [])], [200, 2]);

check('sign out one device', api($a2, 'POST', '/auth/logout')['code'], 200);
check('its token is gone', api($a2, 'GET', '/sync/profiles')['code'], 401);
$out = admin('reset-code', $a['email']);
preg_match('/^\s{4}([0-9a-f]{48})\s*$/m', $out, $m);
$r = req('POST', '/auth/reset-with-token', ['reset_token' => $m[1] ?? '', 'password' => 'smoke password A2']);
check('a reset code from the admin sets a new password', $r['code'], 200);
$a['tok'] = (string) ($r['json']['token'] ?? '');

check('delete account A (owner of the share)', api($a, 'POST', '/auth/delete-account', ['password' => 'smoke password A2'])['code'], 200);
check('the share went with it', api($b, 'POST', '/shares/sync', ['share_id' => $S, 'since' => '', 'records' => []])['code'], 410);
check('delete account B', api($b, 'POST', '/auth/delete-account', ['password' => $b['pw']])['code'], 200);
check('both are gone', [str_contains(admin('list', $tag), 'smoke-'), req('POST', '/auth/login', ['email' => $b['email'], 'password' => $b['pw']])['code']], [false, 401]);

echo $fails ? "$fails FAILED\n" : "ALL PASS\n";
exit($fails ? 1 : 0);
