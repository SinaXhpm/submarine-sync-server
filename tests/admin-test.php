<?php
// The web admin panel and the admin command line.
//   php tests/admin-test.php
declare(strict_types=1);
require __DIR__ . '/lib.php';

wipe();
$pw = 'admin pass phrase 1';
$hash = password_hash($pw, PASSWORD_DEFAULT);

/** A request to the panel; keeps the session cookie it gets. */
function panel(string $method, string $query = '', array $form = [], array $hdr = []): array
{
    global $jar, $panelPath;
    $ch = curl_init(BASE . $panelPath . $query);
    $h = [];
    foreach ($hdr as $k => $v) $h[] = "$k: $v";
    if ($jar) $h[] = 'Cookie: ' . $jar;
    curl_setopt_array($ch, [CURLOPT_CUSTOMREQUEST => $method, CURLOPT_RETURNTRANSFER => true, CURLOPT_HEADER => true, CURLOPT_HTTPHEADER => $h]);
    if ($form) curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($form));
    $resp = (string) curl_exec($ch);
    $hs = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $head = substr($resp, 0, $hs);
    if (preg_match('/^set-cookie: ((?:__Host-|__Secure-)?submarine_admin=([^;]*))/mi', $head, $m)) {
        $jar = $m[2] === '' || $m[2] === 'deleted' ? '' : $m[1];
    }
    return ['code' => curl_getinfo($ch, CURLINFO_RESPONSE_CODE), 'head' => $head, 'body' => substr($resp, $hs)];
}
function csrf_of(string $html): string
{
    return preg_match('/name="csrf" value="([0-9a-f]{64})"/', $html, $m) ? $m[1] : '';
}
$jar = '';
$panelPath = '/admin';

// ===========================================================================
section('off unless a password hash is set');
check('GET /admin: 404 like any unknown path', req('GET', '/admin')['code'], 404);

setConfig(['admin' => ['password_hash' => $hash, 'path' => '/manage']]);
$panelPath = '/manage';
$r = panel('GET');
check('plain http is refused unless switched on, even from this machine', [$r['code'], str_contains($r['body'], 'HTTPS needed')], [403, true]);
setConfig(['admin' => ['password_hash' => $hash, 'path' => '/manage', 'allow_http_local' => true]]);
foreach (['X-Forwarded-For' => '203.0.113.9', 'Forwarded' => 'for=203.0.113.9', 'X-Real-IP' => '203.0.113.9', 'X-Forwarded-Proto' => 'http'] as $hn => $hv) {
    check("switched on, but a request with $hn (it came through a proxy): refused", panel('GET', '', [], [$hn => $hv])['code'], 403);
}
check('the old path stays a 404', req('GET', '/admin')['code'], 404);
$r = panel('GET');
check('the sign-in page', [$r['code'], str_contains($r['body'], 'Admin password')], [200, true]);
check('with a trailing slash too', panel('GET', '/')['code'], 200);
check('a near miss is a 404', req('GET', '/managex')['code'], 404);
preg_match('/^content-security-policy: ([^\r\n]+)/mi', $r['head'], $csp);
check('CSP: no script at all, style by nonce only',
    [str_contains($csp[1] ?? '', "default-src 'none'"), str_contains($csp[1] ?? '', 'script-src'), str_contains($csp[1] ?? '', 'unsafe-inline'), str_contains($csp[1] ?? '', "'nonce-")],
    [true, false, false, true]);
check('not cached, not framed, not indexed', [
    (bool) preg_match('/^cache-control: no-store/mi', $r['head']),
    (bool) preg_match('/^x-frame-options: DENY/mi', $r['head']),
    (bool) preg_match('/^x-robots-tag: noindex/mi', $r['head'])], [true, true, true]);
check('no <script> in the page', stripos($r['body'], '<script'), false);

section('signing in');
$r = panel('POST', '', ['do' => 'login', 'password' => 'wrong']);
check('a wrong password', [$r['code'], str_contains($r['body'], 'Wrong password.')], [401, true]);
check('it is in the event log', (int) one("SELECT COUNT(*) FROM auth_events WHERE event = 'admin_login' AND success = 0"), 1);
for ($i = 0; $i < 4; $i++) panel('POST', '', ['do' => 'login', 'password' => "wrong $i"]);
$r = panel('POST', '', ['do' => 'login', 'password' => $pw]);
check('after five failures even the right one waits', [$r['code'], str_contains($r['body'], 'Too many failed tries')], [401, true]);
clearRL();
$pdo->prepare('INSERT INTO rate_limits (bucket, window_start, hits) VALUES (?, ?, 50)')->execute(['admin:login:all', intdiv(time(), 3600) * 3600]);
$r = panel('POST', '', ['do' => 'login', 'password' => $pw]);
check('50 failures in an hour from anywhere close it too', str_contains($r['body'], 'Too many failed tries'), true);
clearRL();
$r = panel('POST', '', ['do' => 'login', 'password' => $pw]);
check('the right password: redirect, cookie', [$r['code'], $jar !== ''], [303, true]);
check('the cookie: HttpOnly, SameSite=Strict, the panel\'s own path', [
    (bool) preg_match('/^set-cookie: submarine_admin=[^\r\n]*httponly/mi', $r['head']),
    (bool) preg_match('/^set-cookie: submarine_admin=[^\r\n]*samesite=strict/mi', $r['head']),
    (bool) preg_match('/^set-cookie: submarine_admin=[^\r\n]*path=\/manage/mi', $r['head'])], [true, true, true]);
check('only an HMAC of the cookie is stored', (int) one('SELECT COUNT(*) FROM admin_sessions WHERE token_hash = ?', [substr($jar, strpos($jar, '=') + 1)]), 0);
$r = panel('GET');
check('the dashboard opens', [$r['code'], str_contains($r['body'], 'Invite someone'), str_contains($r['body'], 'Accounts (')], [200, true, true]);
$csrf = csrf_of($r['body']);
check('it carries a CSRF token', strlen($csrf), 64);

section('the accounts list, escaped');
$evil = "x'\"><img src=x onerror=alert(1)>@evil.test";
$pdo->prepare('INSERT INTO users (email, password_hash, status) VALUES (?, "x", "active")')->execute([$evil]);
$a = mkuser('alice@stage.test');
api($a, 'POST', '/sync', ['profile' => 'p1', 'since' => '', 'records' => [rec('servers', (int) (microtime(true) * 1000), str_repeat('ab', 1000))], 'name' => 'P']);
$r = panel('GET');
check('a hostile email shows as text', [str_contains($r['body'], '<img src=x'), str_contains($r['body'], '&lt;img src=x onerror=alert(1)&gt;')], [false, true]);
check('alice is listed with her storage', (bool) preg_match('#alice@stage\.test</td>.*?<td>1</td><td>1000 B</td>#s', $r['body']), true);
check('totals: 1 personal profile', (bool) preg_match('#<b>1</b><span>personal profiles#', $r['body']), true);
check('search', [str_contains(panel('GET', '?q=alice')['body'], 'alice@stage.test'), str_contains(panel('GET', '?q=alice')['body'], 'evil.test')], [true, false]);
check('no record content anywhere', str_contains($r['body'], str_repeat('ab', 50)), false);

section('actions need the CSRF token');
$r = panel('POST', '', ['do' => 'suspend', 'uid' => $a['id']]);
check('without it: nothing happens', [$r['code'], one('SELECT status FROM users WHERE id = ?', [$a['id']])], [303, 'active']);
check('and the page says why', str_contains(panel('GET')['body'], 'out of date'), true);
$r = panel('POST', '', ['do' => 'suspend', 'uid' => $a['id'], 'csrf' => str_repeat('0', 64)]);
check('with a wrong one: nothing', one('SELECT status FROM users WHERE id = ?', [$a['id']]), 'active');

section('invitations and reset codes are shown once');
$r = panel('POST', '', ['do' => 'invite', 'csrf' => $csrf, 'email' => 'Bob@Stage.test']);
preg_match('/<div class="code">([0-9a-f]{48})<\/div>/', $r['body'], $m);
check('invite: the code is on the page', [$r['code'], strlen($m[1] ?? '')], [200, 48]);
check('a pending account', one('SELECT status FROM users WHERE email = ?', ['bob@stage.test']), 'pending');
$v = req('GET', '/auth/verify?token=' . ($m[1] ?? ''));
check('the code works in the app\'s flow', $v['code'], 200);
check('the invitation is in the event log', (int) one("SELECT COUNT(*) FROM auth_events WHERE event = 'admin_invite' AND email = 'bob@stage.test'"), 1);
$r = panel('POST', '', ['do' => 'invite', 'csrf' => $csrf, 'email' => 'alice@stage.test']);
check('inviting an existing account: refused, said why', [$r['code'], str_contains(panel('GET')['body'], 'already has an account')], [303, true]);
$r = panel('POST', '', ['do' => 'reset', 'csrf' => $csrf, 'uid' => $a['id']]);
preg_match('/<div class="code">([0-9a-f]{48})<\/div>/', $r['body'], $m);
check('a reset code on the page', strlen($m[1] ?? ''), 48);
$x = req('POST', '/auth/reset-with-token', ['reset_token' => $m[1] ?? '', 'password' => 'alice new pass 1']);
check('it resets the password', $x['code'], 200);
check('the code is not stored in clear', (int) one('SELECT COUNT(*) FROM verify_tokens WHERE token_hash = ?', [$m[1] ?? '']), 0);

section('suspend, sign out, delete');
$a = ['id' => $a['id'], 'tok' => (string) $x['json']['token']];
panel('POST', '', ['do' => 'signout', 'csrf' => $csrf, 'uid' => $a['id']]);
check('sign out everywhere: the token is dead', api($a, 'GET', '/sync/profiles')['code'], 401);
check('and the page says so', str_contains(panel('GET')['body'], 'Signed out of 1 device.'), true);
panel('POST', '', ['do' => 'suspend', 'csrf' => $csrf, 'uid' => $a['id']]);
check('suspended', one('SELECT status FROM users WHERE id = ?', [$a['id']]), 'banned');
panel('POST', '', ['do' => 'unsuspend', 'csrf' => $csrf, 'uid' => $a['id']]);
check('unsuspended', one('SELECT status FROM users WHERE id = ?', [$a['id']]), 'active');
check('every action is in the log', (int) one("SELECT COUNT(*) FROM auth_events WHERE user_id = ? AND event IN ('admin_signout','admin_suspend','admin_unsuspend','admin_reset_code')", [$a['id']]), 4);
panel('POST', '', ['do' => 'delete', 'csrf' => $csrf, 'uid' => $a['id'], 'confirm' => 'not her email']);
check('delete without the right email typed: nothing', [(int) one('SELECT COUNT(*) FROM users WHERE id = ?', [$a['id']]), str_contains(panel('GET')['body'], 'type the account')], [1, true]);
panel('POST', '?q=alice', ['do' => 'delete', 'csrf' => $csrf, 'uid' => $a['id'], 'confirm' => 'ALICE@stage.test ']);
check('with it: gone, with its records', [(int) one('SELECT COUNT(*) FROM users WHERE id = ?', [$a['id']]), (int) one('SELECT COUNT(*) FROM sync_records WHERE user_id = ?', [$a['id']])], [0, 0]);
check('logged without the address', (int) one("SELECT COUNT(*) FROM auth_events WHERE event = 'admin_delete' AND email IS NULL AND detail = ?", ['uid=' . $a['id']]), 1);
check('the account\'s own log rows went with it', (int) one('SELECT COUNT(*) FROM auth_events WHERE user_id = ?', [$a['id']]), 0);

section('the session ends');
$pdo->exec('UPDATE admin_sessions SET seen_at = seen_at - 3600');
$r = panel('GET');
check('after 30 idle minutes: the sign-in page', str_contains($r['body'], 'Admin password'), true);
panel('POST', '', ['do' => 'login', 'password' => $pw]);
check('signed in again', str_contains(panel('GET')['body'], 'Invite someone'), true);
setConfig(['admin' => ['password_hash' => password_hash('another admin pass', PASSWORD_DEFAULT), 'path' => '/manage', 'allow_http_local' => true]]);
check('a new password hash ends every session', str_contains(panel('GET')['body'], 'Admin password'), true);
setConfig(['admin' => ['password_hash' => $hash, 'path' => '/manage', 'allow_http_local' => true]]);
panel('POST', '', ['do' => 'login', 'password' => $pw]);
$csrf = csrf_of(panel('GET')['body']);
panel('POST', '', ['do' => 'logout', 'csrf' => $csrf]);
check('sign out: back to the sign-in page, the row is gone', [str_contains(panel('GET')['body'], 'Admin password'), (int) one('SELECT COUNT(*) FROM admin_sessions')], [true, 0]);

section('HTTPS through a trusted proxy');
setConfig(['admin' => ['password_hash' => $hash, 'path' => '/manage'], 'security' => ['trusted_proxies' => ['127.0.0.1']]]);
$jar = '';
$r = panel('POST', '', ['do' => 'login', 'password' => $pw], ['X-Forwarded-Proto' => 'https']);
check('the cookie is __Host- and Secure', [(bool) preg_match('/^set-cookie: __Host-submarine_admin=[^\r\n]*secure/mi', $r['head'])], [true]);
$r = panel('GET', '', [], ['X-Forwarded-Proto' => 'https']);
check('and HSTS is sent', [(bool) preg_match('/^strict-transport-security:/mi', $r['head']), str_contains($r['body'], 'Invite someone')], [true, true]);
restoreConfig();

section('sign-in tries at once are counted before any is checked');
setConfig(['admin' => ['password_hash' => $hash, 'path' => '/manage', 'allow_http_local' => true]]);
clearRL();
$pdo->exec("DELETE FROM auth_events WHERE event = 'admin_login'");
$mh = curl_multi_init();
$hs = [];
for ($i = 0; $i < 12; $i++) {
    $ch = curl_init(BASE . '/manage');
    curl_setopt_array($ch, [CURLOPT_POST => true, CURLOPT_RETURNTRANSFER => true, CURLOPT_POSTFIELDS => http_build_query(['do' => 'login', 'password' => "wrong $i"])]);
    curl_multi_add_handle($mh, $ch);
    $hs[] = $ch;
}
do { curl_multi_exec($mh, $running); if ($running) curl_multi_select($mh, 1.0); } while ($running);
check('12 at once: at most 5 passwords checked', (int) one("SELECT COUNT(*) FROM auth_events WHERE event = 'admin_login' AND detail = 'bad_password'") <= 5, true);
clearRL();
restoreConfig();

section('under a base path');
setConfig(['base_path' => '/sub', 'admin' => ['password_hash' => $hash, 'path' => '/manage', 'allow_http_local' => true]]);
$panelPath = '/sub/manage';
$jar = '';
$r = panel('GET');
check('the panel at /sub/manage', [$r['code'], str_contains($r['body'], 'action="/sub/manage"')], [200, true]);
check('not at /manage', req('GET', '/manage')['code'], 404);
setConfig(['base_path' => '/sub', 'admin' => ['password_hash' => $hash, 'path' => '/manage'], 'security' => ['trusted_proxies' => ['127.0.0.1']]]);
$jar = '';
$r = panel('POST', '', ['do' => 'login', 'password' => $pw], ['X-Forwarded-Proto' => 'https']);
check('over HTTPS: a __Secure- cookie kept to the panel\'s path', [
    (bool) preg_match('/^set-cookie: __Secure-submarine_admin=[^\r\n]*path=\/sub\/manage;[^\r\n]*secure/mi', $r['head']),
    (bool) preg_match('/^set-cookie: __Host-/mi', $r['head'])], [true, false]);
restoreConfig();

// ===========================================================================
section('the command line');
[$rc, $out] = cli('check');
check('check', [$rc, str_contains($out, 'Settings: OK'), str_contains($out, 'Database: OK'), str_contains($out, 'Password check:')], [0, true, true, true]);
[$rc, $out] = cli('list');
check('list', [$rc, str_contains($out, 'bob@stage.test')], [0, true]);
[$rc, $out] = cli('list', 'zzz-nobody');
check('list with a filter that matches nothing', [$rc, trim($out)], [0, 'No accounts.']);
$c = mkuser('carol@stage.test');
[$rc, $out] = cli('signout', 'carol@stage.test');
check('signout', [$rc, api($c, 'GET', '/sync/profiles')['code']], [0, 401]);
[$rc, $out] = cli('delete', 'carol@stage.test', '--yes');
check('delete --yes', [$rc, (int) one('SELECT COUNT(*) FROM users WHERE email = ?', ['carol@stage.test'])], [0, 0]);
[$rc, $out] = cli('delete', 'nobody@stage.test', '--yes');
check('delete of an unknown account', $rc, 1);
[$rc, $out] = cli('unknown-command');
check('an unknown command', $rc, 2);
[$rc, $out] = cli('suspend');
check('no email given', [$rc, str_contains($out, 'Give the email')], [1, true]);
$cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(ROOT . '/bin/admin.php') . ' hash-password';
$proc = proc_open($cmd, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
fwrite($pipes[0], "a long admin password\na long admin password\n");
fclose($pipes[0]);
$out = stream_get_contents($pipes[1]);
proc_close($proc);
preg_match("/SUBMARINE_ADMIN_PASSWORD_HASH='([^']+)'/", $out, $m);
check('hash-password prints a hash that matches', password_verify('a long admin password', $m[1] ?? ''), true);
$proc = proc_open($cmd, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
fwrite($pipes[0], "short\nshort\n");
fclose($pipes[0]);
$err = stream_get_contents($pipes[2]);
$rc = proc_close($proc);
check('a short admin password is refused', [$rc, str_contains($err, '12 characters')], [1, true]);
foreach (['bin/admin.php', 'bin/cron.php', 'bin/migrate.php'] as $f) {
    $r = req('GET', '/' . $f);
    check("$f over HTTP: never run (it is outside public/)", $r['code'], 404);
}
$out = []; $rc = 0;
exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(ROOT . '/bin/cron.php') . ' 2>&1', $out, $rc);
check('cron runs', [$rc, str_contains(implode("\n", $out), 'expired sign-ins:')], [0, true]);
$pid = mkpending('stale@stage.test');
$pdo->prepare('UPDATE users SET created_at = NOW() - INTERVAL 8 DAY WHERE id = ?')->execute([$pid]);
exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(ROOT . '/bin/cron.php') . ' 2>&1', $out, $rc);
check('cron removes a sign-up never finished after a week', (int) one('SELECT COUNT(*) FROM users WHERE id = ?', [$pid]), 0);
$out = []; $rc = 0;
exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(ROOT . '/bin/migrate.php') . ' 2>&1', $out, $rc);
check('migrate runs again without harm', [$rc, str_contains(implode("\n", $out), 'Database ready')], [0, true]);

done();
