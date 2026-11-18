<?php
// The API end to end: what the released apps do, request rules, record
// checks, the caps, sign-up modes and invitations, the base path, client IPs.
//   php tests/api-test.php
declare(strict_types=1);
require __DIR__ . '/lib.php';

wipe();
$now = (int) (microtime(true) * 1000);

// ===========================================================================
section('what the released apps do');
$alice = mkuser('alice@stage.test');
$bob   = mkuser('bob@stage.test');
check('login gives a token', strlen($alice['tok']), 64);
$r = req('GET', '/health');
check('health', [$r['code'], $r['json']['ok'] ?? null], [200, true]);
$r = req('GET', '/api/health');
check('health under /api too', [$r['code'], $r['json']['ok'] ?? null], [200, true]);

$recs = [rec('servers', $now), rec('servers', $now + 1), rec('folders', $now + 2)];
$r = api($alice, 'POST', '/sync', ['profile' => 'pa', 'since' => '', 'records' => $recs, 'name' => 'Work']);
check('sync push', [$r['code'], count($r['json']['records'] ?? [])], [200, 3]);
$r = api($alice, 'POST', '/sync', ['profile' => 'pa', 'since' => $recs[1]['updated_at'], 'records' => []]);
check('sync pull since', [$r['code'], count($r['json']['records'] ?? [])], [200, 1]);
$tomb = ['uuid' => $recs[0]['uuid'], 'entity_type' => 'servers', 'updated_at' => stamp($now + 10), 'deleted' => true];
$esc  = ['uuid' => bin2hex(random_bytes(16)), 'entity_type' => 'dek_escrow', 'updated_at' => '000000000000000:00000:0', 'deleted' => false, 'blob' => bin2hex(random_bytes(60))];
$bf   = ['uuid' => bin2hex(random_bytes(16)), 'entity_type' => 'monitor_configs', 'updated_at' => '000000000000001:00000:backfill', 'deleted' => false, 'blob' => bin2hex(random_bytes(20))];
$r = api($alice, 'POST', '/sync', ['profile' => 'pa', 'since' => '', 'records' => array_merge($recs, [$tomb, $esc, $bf]), 'name' => 'Work']);
check('push with a deletion, the escrow key and a backfilled row', [$r['code'], count($r['json']['records'] ?? [])], [200, 5]);
check('deletion stored', (int) one('SELECT deleted FROM sync_records WHERE uuid = ?', [$recs[0]['uuid']]), 1);
$r = api($alice, 'GET', '/sync/profiles');
$p = $r['json']['profiles'][0] ?? [];
check('profile list', [$r['code'], $p['name'] ?? null, $p['records'] ?? null, $p['live_records'] ?? null], [200, 'Work', 5, 3]);
$r = api($alice, 'GET', '/api/sync/profiles');
check('the same under /api', $r['code'], 200);

$pubA = bin2hex(random_bytes(32));
$pubB = bin2hex(random_bytes(32));
$r = api($alice, 'POST', '/keys/publish', ['public_key' => $pubA, 'wrapped_privkey' => bin2hex(random_bytes(60)), 'enc_salt' => bin2hex(random_bytes(16))]);
check('publish key', [$r['code'], $r['json']['created'] ?? null], [200, true]);
api($bob, 'POST', '/keys/publish', ['public_key' => $pubB, 'wrapped_privkey' => bin2hex(random_bytes(60)), 'enc_salt' => bin2hex(random_bytes(16))]);
$r = api($alice, 'GET', '/keys/me');
check('my key back', [$r['code'], $r['json']['public_key'] ?? null], [200, $pubA]);
$r = api($alice, 'POST', '/keys/lookup', ['email' => 'bob@stage.test']);
check('look up a key', [$r['code'], $r['json']['public_key'] ?? null], [200, $pubB]);

$sid = bin2hex(random_bytes(16));
$r = api($alice, 'POST', '/shares/create', ['share_id' => $sid, 'name' => 'Team', 'sealed_dek' => bin2hex(random_bytes(48))]);
check('create a share', $r['code'], 200);
$r = api($alice, 'POST', '/shares/invite', ['share_id' => $sid, 'email' => 'bob@stage.test', 'role' => 'editor', 'sealed_dek' => bin2hex(random_bytes(48))]);
check('invite', $r['code'], 200);
$r = api($bob, 'POST', '/shares/list');
check('invitee sees it pending', [$r['code'], $r['json']['shares'][0]['status'] ?? null], [200, 'pending']);
$r = api($bob, 'POST', '/shares/accept', ['share_id' => $sid]);
check('accept', $r['code'], 200);
$srecs = [rec('servers', $now + 20), rec('servers', $now + 21)];
$r = api($alice, 'POST', '/shares/sync', ['share_id' => $sid, 'since' => '', 'records' => $srecs]);
check('owner pushes to the share', [$r['code'], count($r['json']['records'] ?? [])], [200, 2]);
$r = api($bob, 'POST', '/shares/sync', ['share_id' => $sid, 'since' => '', 'records' => [rec('servers', $now + 22)]]);
check('editor pushes and pulls', [$r['code'], count($r['json']['records'] ?? [])], [200, 3]);
$r = api($bob, 'POST', '/shares/dek', ['share_id' => $sid]);
check('member gets the sealed key', [$r['code'], $r['json']['role'] ?? null], [200, 'editor']);
$r = api($alice, 'POST', '/shares/members', ['share_id' => $sid]);
check('member list', [$r['code'], count($r['json']['members'] ?? [])], [200, 2]);
api($alice, 'POST', '/shares/set-role', ['share_id' => $sid, 'member_user_id' => $bob['id'], 'role' => 'user']);
$r = api($bob, 'POST', '/shares/sync', ['share_id' => $sid, 'since' => '', 'records' => [rec('servers', $now + 23)]]);
check('viewer can not push', [$r['code'], $r['json']['error'] ?? null], [403, 'read_only']);
$r = api($bob, 'POST', '/shares/sync', ['share_id' => $sid, 'since' => '', 'records' => []]);
check('viewer pulls', [$r['code'], count($r['json']['records'] ?? [])], [200, 3]);
api($alice, 'POST', '/shares/revoke', ['share_id' => $sid, 'member_user_id' => $bob['id']]);
$r = api($bob, 'POST', '/shares/sync', ['share_id' => $sid, 'since' => '', 'records' => []]);
check('revoked member is out', $r['code'], 403);
$r = api($alice, 'POST', '/shares/delete', ['share_id' => $sid]);
check('delete the share', [$r['code'], (int) one('SELECT COUNT(*) FROM shared_records WHERE share_id = ?', [$sid])], [200, 0]);
$r = api($alice, 'POST', '/sync/delete', ['profile' => 'pa']);
check('delete a cloud profile', [$r['code'], $r['json']['deleted'] ?? null], [200, 5]);
$r = req('POST', '/auth/request-login', ['email' => 'alice@stage.test']);
check('ask for a sign-in code (mail off: the same answer)', [$r['code'], $r['json']['status'] ?? null], [200, 'ok']);
$r = api($alice, 'POST', '/auth/logout');
check('sign out (no body)', $r['code'], 200);
$r = api($alice, 'GET', '/keys/me');
check('token gone after sign-out', $r['code'], 401);
$r = req('GET', '/keys/me', null, ['Authorization' => 'Bearer ' . $bob['tok']]);
check('Authorization: Bearer works too', $r['code'], 200);

// ===========================================================================
section('what is not here');
foreach ([['POST', '/feedback'], ['GET', '/profiles'], ['POST', '/profiles'], ['GET', '/profiles/1/blob'], ['GET', '/admin'], ['GET', '/nothing']] as [$m, $p]) {
    $r = req($m, $p, $m === 'POST' ? ['x' => 1] : null);
    check("$m $p: 404", [$r['code'], $r['json']['error'] ?? null], [404, 'no_route']);
}
$r = req('GET', '/' . str_repeat('a', 3000));
check('a long unknown path is not echoed back', [$r['code'], strlen($r['body']) < 200], [404, true]);

// ===========================================================================
section('sign-up by invitation (the default)');
$r = req('POST', '/auth/signup', ['email' => 'newbie@stage.test']);
check('sign-up is closed', [$r['code'], $r['json']['error'] ?? null], [403, 'signup_closed']);
check('it says what to do', str_contains((string) ($r['json']['message'] ?? ''), 'Have a verify token?'), true);
check('no account was made', (int) one('SELECT COUNT(*) FROM users WHERE email = ?', ['newbie@stage.test']), 0);
[$rc, $out] = cli('invite', 'Invited@Stage.test');
check('cli invite', $rc, 0);
preg_match('/^\s{4}([0-9a-f]{48})$/m', $out, $m);
$code = $m[1] ?? '';
check('it prints a code', strlen($code), 48);
check('a pending account, email in lower case', one('SELECT status FROM users WHERE email = ?', ['invited@stage.test']), 'pending');
$r = req('GET', '/auth/verify?token=' . $code);
check('the code verifies, as the apps do it', [$r['code'], $r['json']['email'] ?? null, strlen((string) ($r['json']['claim_token'] ?? ''))], [200, 'invited@stage.test', 48]);
$r = req('POST', '/auth/set-password', ['claim_token' => $r['json']['claim_token'] ?? '', 'password' => 'invited pass 1']);
check('then a password, and a sign-in', [$r['code'], strlen((string) ($r['json']['token'] ?? ''))], [200, 64]);
check('the account is active', one('SELECT status FROM users WHERE email = ?', ['invited@stage.test']), 'active');
$r = req('GET', '/auth/verify?token=' . $code);
check('the code works once', [$r['code'], $r['json']['error'] ?? null], [400, 'verify_failed']);
[$rc, $out] = cli('invite', 'invited@stage.test');
check('inviting an active account is refused', [$rc, str_contains($out, 'already has an account')], [1, true]);
[$rc, $out] = cli('invite', 'not an email');
check('a bad address is refused', $rc, 1);
[$rc, $out] = cli('invite', 'again@stage.test');
preg_match('/^\s{4}([0-9a-f]{48})$/m', $out, $m1);
[$rc, $out] = cli('invite', 'again@stage.test');
preg_match('/^\s{4}([0-9a-f]{48})$/m', $out, $m2);
check('a new invitation replaces the old code', [req('GET', '/auth/verify?token=' . ($m1[1] ?? ''))['code'], req('GET', '/auth/verify?token=' . ($m2[1] ?? ''))['code']], [400, 200]);

section('reset codes from the command line');
[$rc, $out] = cli('reset-code', 'invited@stage.test');
preg_match('/^\s{4}([0-9a-f]{48})$/m', $out, $m);
check('cli reset-code', [$rc, strlen($m[1] ?? '')], [0, 48]);
$r = req('POST', '/auth/reset-with-token', ['reset_token' => $m[1] ?? '', 'password' => 'new invited pass 2']);
check('it sets a new password', [$r['code'], strlen((string) ($r['json']['token'] ?? ''))], [200, 64]);
$r = req('POST', '/auth/login', ['email' => 'invited@stage.test', 'password' => 'new invited pass 2']);
check('which signs in', $r['code'], 200);
[$rc, $out] = cli('reset-code', 'nobody@stage.test');
check('no account: refused', [$rc, str_contains($out, 'no account')], [1, true]);
[$rc, $out] = cli('reset-code', 'again@stage.test');
check('not finished: refused', [$rc, str_contains($out, 'invitation')], [1, true]);

section('open sign-up');
setConfig(['signup' => 'open']);
$r = req('POST', '/auth/signup', ['email' => 'x@stage.test']);
check('open needs mail: the server refuses to run with that setting', [$r['code'], $r['json']['error'] ?? null], [500, 'misconfigured']);
setConfig(['signup' => 'open', 'mail' => ['transport' => 'smtp', 'smtp_host' => '127.0.0.1', 'smtp_port' => 9, 'smtp_security' => 'none', 'from_address' => 'sync@stage.test']]);
$r = req('POST', '/auth/signup', ['email' => 'opened@stage.test']);
check('with mail set up: "check your inbox"', [$r['code'], $r['json']['status'] ?? null], [200, 'pending']);
check('a pending account with a code', (int) one('SELECT COUNT(*) FROM verify_tokens v JOIN users u ON u.id = v.user_id WHERE u.email = ? AND v.purpose = "verify"', ['opened@stage.test']), 1);
$r = req('POST', '/auth/signup', ['email' => 'invited@stage.test']);
check('an existing account gets the same answer', [$r['code'], $r['json']['status'] ?? null], [200, 'pending']);

// The headers too: every branch answers with Content-Length and
// Connection: close where PHP can't end the request itself.
$heads = function (string $path, string $email): string {
    clearRL();
    $h = req('POST', $path, ['email' => $email])['headers'];
    $names = [];
    foreach (preg_split('/\r?\n/', trim($h)) as $l) {
        if (preg_match('/^([A-Za-z-]+):/', $l, $m) && strcasecmp($m[1], 'Date') !== 0) $names[] = strtolower($m[1]);
    }
    sort($names);
    return implode(',', $names);
};
foreach (['/auth/signup', '/auth/request-reset', '/auth/request-login'] as $p) {
    $known = $heads($p, 'invited@stage.test');
    check("$p: the same headers for a registered and an unknown address", [$known, $heads($p, 'nobody-' . bin2hex(random_bytes(3)) . '@stage.test')], [$known, $known]);
    check("$p: Connection: close on the registered one too", str_contains($known, 'connection'), true);
}

// A stranger's sign-up with an address the admin invited doesn't cancel the invitation.
[, $out] = cli('invite', 'guest@stage.test');
preg_match('/^\s{4}([0-9a-f]{48})$/m', $out, $m);
clearRL();
req('POST', '/auth/signup', ['email' => 'guest@stage.test']);
check('an invitation survives a sign-up with the same address', req('GET', '/auth/verify?token=' . ($m[1] ?? ''))['code'], 200);

setConfig(['signup' => 'open', 'max_accounts' => (int) one('SELECT COUNT(*) FROM users WHERE status <> "pending"'), 'mail' => ['transport' => 'smtp', 'smtp_host' => '127.0.0.1', 'smtp_port' => 9, 'smtp_security' => 'none', 'from_address' => 'sync@stage.test']]);
clearRL();
$r = req('POST', '/auth/signup', ['email' => 'onemore@stage.test']);
check('max_accounts reached: no new account', [$r['code'], $r['json']['error'] ?? null, (int) one('SELECT COUNT(*) FROM users WHERE email = ?', ['onemore@stage.test'])], [403, 'signup_full', 0]);
$r2 = req('POST', '/auth/signup', ['email' => 'invited@stage.test']);
check('a full server answers a registered address the same way', [$r2['code'], $r2['body']], [403, $r['body']]);
restoreConfig();

// Only finished accounts count: sign-ups nobody finishes can't fill the server.
$finished = (int) one('SELECT COUNT(*) FROM users WHERE status <> "pending"');
setConfig(['signup' => 'open', 'max_accounts' => $finished + 1, 'mail' => ['transport' => 'smtp', 'smtp_host' => '127.0.0.1', 'smtp_port' => 9, 'smtp_security' => 'none', 'from_address' => 'sync@stage.test']]);
for ($i = 1; $i <= 5; $i++) mkpending("never-finished$i@stage.test");
clearRL();
$r = req('POST', '/auth/signup', ['email' => 'room-left@stage.test']);
check('unfinished sign-ups leave room for a real one', [$r['code'], $r['json']['status'] ?? null], [200, 'pending']);
$late = mkpending('late-signup@stage.test');
$lateCode = mktoken($late, 'verify');
mkuser('fills-the-last-place@stage.test');
clearRL();
$r = req('GET', '/auth/verify?token=' . $lateCode);
check('once full, a sign-up code can\'t finish an account (the code stays usable)', [$r['code'], $r['json']['error'] ?? null,
    one('SELECT used_at FROM verify_tokens WHERE user_id = ?', [$late])], [403, 'signup_full', null]);
$inv = mkpending('admin-invited@stage.test');
$invCode = mktoken($inv, 'invite');
check('an invitation the admin made still works on a full server', req('GET', '/auth/verify?token=' . $invCode)['code'], 200);
restoreConfig();

// Email addresses: the plain printable form only.
foreach (['first.last+tag@sub.example.co' => true, "o'neil@example.com" => true, 'a@b' => false,
          '"quoted"@example.com' => false, "\"a\x1b[8mb\"@example.com" => false, '"a\\ b"@example.com' => false,
          "x\n@example.com" => false, 'a b@example.com' => false, 'ab@-example.com' => false] as $addr => $ok) {
    check('validEmail(' . json_encode($addr) . ')', \Submarine\Lib\Util::validEmail($addr), $ok);
}
clearRL();
$r = req('POST', '/auth/login', ['email' => "\"a\x1b[8mb\"@example.com", 'password' => 'correct horse 1']);
check('a quoted address with control bytes is refused', [$r['code'], $r['json']['error'] ?? null], [400, 'invalid_input']);

// ===========================================================================
section('JSON bodies only');
$a2 = mkuser('alice2@stage.test');
$login = json_encode(['email' => 'alice2@stage.test', 'password' => 'correct horse 1']);
$r = req('POST', '/auth/login', $login, [], 'text/plain');
check('text/plain body refused', [$r['code'], $r['json']['error'] ?? null], [415, 'unsupported_media_type']);
$r = req('POST', '/auth/login', 'email=alice2%40stage.test&password=correct+horse+1', [], 'application/x-www-form-urlencoded');
check('form body refused', $r['code'], 415);
$r = req('POST', '/auth/login', $login, [], 'multipart/form-data; boundary=x');
check('multipart body refused', $r['code'], 415);
$r = req('POST', '/auth/login', $login, [], 'application/json; charset=utf-8');
check('application/json with a charset works', $r['code'], 200);
$r = req('POST', '/auth/login', $login, [], 'Application/JSON');
check('type is case-insensitive', $r['code'], 200);
$r = api($a2, 'POST', '/shares/list');
check('a request with no body still works', $r['code'], 200);

section('security headers on JSON');
$r = req('GET', '/health');
$h = strtolower($r['headers']);
check('X-Frame-Options', str_contains($h, 'x-frame-options: deny'), true);
check('CSP', str_contains($h, "content-security-policy: default-src 'none'; frame-ancestors 'none'"), true);
check('no-store', str_contains($h, 'cache-control: no-store'), true);
check('no X-Powered-By', str_contains($h, 'x-powered-by'), false);

section('passwords');
$p = mkpending('pw@stage.test');
$claim = mktoken($p, 'claim');
$r = req('POST', '/auth/set-password', ['claim_token' => $claim, 'password' => 'short']);
check('too short', [$r['code'], $r['json']['error'] ?? null], [400, 'invalid_input']);
$r = req('POST', '/auth/set-password', ['claim_token' => $claim, 'password' => "has a\0nul inside"]);
check('a NUL byte is refused, not a 500', [$r['code'], $r['json']['error'] ?? null], [400, 'invalid_input']);
$r = req('POST', '/auth/set-password', ['claim_token' => $claim, 'password' => str_repeat('x', 73)]);
check('over 72 bytes (bcrypt would ignore the rest) is refused', [$r['code'], str_contains((string) ($r['json']['message'] ?? ''), '72 bytes')], [400, true]);
$r = req('POST', '/auth/set-password', ['claim_token' => $claim, 'password' => ['an', 'array']]);
check('a password that is not text is refused, not a 500', $r['code'], 400);
$r = req('POST', '/auth/login', ['email' => 'alice2@stage.test', 'password' => "x\0y"]);
check('a NUL in a sign-in is just a wrong password', $r['code'], 401);
$r = req('POST', '/auth/set-password', ['claim_token' => $claim, 'password' => str_repeat('x', 72)]);
check('72 bytes is taken', $r['code'], 200);
$late = mktoken($p, 'claim');
$r = req('POST', '/auth/set-password', ['claim_token' => $late, 'password' => 'someone elses pass']);
check('a claim for an account that already has its password is refused', [$r['code'], $r['json']['error'] ?? null], [400, 'invalid_claim']);
check('and the password is unchanged', password_verify(str_repeat('x', 72), (string) one('SELECT password_hash FROM users WHERE id = ?', [$p])), true);
$late = mktoken($p, 'verify');
check('so is a verify code for it', req('GET', '/auth/verify?token=' . $late)['code'], 400);

section('fields of the wrong type: refused, never a 500 or a warning');
foreach ([['/auth/login', ['email' => ['a@b.c'], 'password' => 'x']], ['/auth/signup', ['email' => ['x' => 1]]],
          ['/auth/request-reset', ['email' => 5]], ['/auth/verify', ['token' => ['t']]], ['/auth/login-with-link', ['login_token' => [1]]],
          ['/auth/reset-with-token', ['reset_token' => ['x'], 'password' => 'long enough pw']]] as [$path, $body]) {
    clearRL();
    $r = req('POST', $path, $body);
    check("$path with an array or number", $r['code'] >= 400 && $r['code'] < 500 || $r['code'] === 200, true);
}
$r = api($a2, 'POST', '/sync', ['profile' => ['x'], 'since' => '', 'records' => []]);
check('/sync with a profile that is an array', $r['code'], 400);
$r = api($a2, 'POST', '/shares/create', ['share_id' => [str_repeat('a', 32)], 'name' => 'x', 'sealed_dek' => 'ab']);
check('/shares/create with an array id', $r['code'], 400);
$r = api($a2, 'POST', '/keys/lookup', ['email' => ['bob@stage.test']]);
check('/keys/lookup with an array email', $r['code'], 400);

section('sync stamps and record shapes');
$u = mkuser('stamps@stage.test');
$good   = rec('servers', $now);
$soon   = rec('servers', $now + 3600 * 1000);
$future = rec('servers', $now + 2 * 86400 * 1000);
$shape  = rec('servers', $now); $shape['updated_at'] = 'zzz';
$long   = rec('servers', $now); $long['updated_at'] = stamp($now, 0, str_repeat('a', 27));
$upper  = rec('Servers', $now);
$html   = rec('<b>x</b>', $now);
$arr    = rec('servers', $now); $arr['blob'] = ['not', 'a', 'string'];
$nl     = rec('servers', $now); $nl['uuid'] .= "\n";
$r = api($u, 'POST', '/sync', ['profile' => 'ps', 'since' => '', 'records' => [$good, $soon, $future, $shape, $long, $upper, $html, $arr, $nl]]);
$kept = array_column($r['json']['records'] ?? [], 'uuid');
check('push answered', $r['code'], 200);
check('valid stamp kept', in_array($good['uuid'], $kept, true), true);
check('an hour ahead is kept', in_array($soon['uuid'], $kept, true), true);
check('two days ahead is dropped', in_array($future['uuid'], $kept, true), false);
check('a stamp in another shape is dropped', in_array($shape['uuid'], $kept, true), false);
check('a node part over 26 is dropped', in_array($long['uuid'], $kept, true), false);
check('an odd entity type is dropped', [in_array($upper['uuid'], $kept, true), in_array($html['uuid'], $kept, true)], [false, false]);
check('a blob that is not a string is dropped', in_array($arr['uuid'], $kept, true), false);
check('a uuid with a newline is dropped', (int) one('SELECT COUNT(*) FROM sync_records WHERE uuid LIKE ?', [trim($nl['uuid']) . '%']), 0);
$tb = rec('servers', $now + 5, bin2hex(random_bytes(500)), true);
$r = api($u, 'POST', '/sync', ['profile' => 'ps', 'since' => '', 'records' => [$tb]]);
check('a deletion that brings a blob is stored without it',
    [$r['code'], (int) one('SELECT `blob` IS NULL FROM sync_records WHERE uuid = ?', [$tb['uuid']])], [200, 1]);
$r = api($u, 'POST', '/sync', ['profile' => "p\ns", 'since' => '', 'records' => []]);
check('a profile id with a newline is refused', $r['code'], 400);
$ssid = bin2hex(random_bytes(16));
$r = api($u, 'POST', '/shares/create', ['share_id' => $ssid . "\n", 'name' => 'S', 'sealed_dek' => 'ab']);
check('a share id with a newline is refused', $r['code'], 400);
api($u, 'POST', '/shares/create', ['share_id' => $ssid, 'name' => 'S', 'sealed_dek' => 'ab']);
$tbs = rec('servers', $now + 8, bin2hex(random_bytes(500)), true);
$r = api($u, 'POST', '/shares/sync', ['share_id' => $ssid, 'since' => '', 'records' => [$tbs, $future, rec('servers', $now)]]);
check('share push: future stamp dropped, deletion without blob',
    [$r['code'], count($r['json']['records'] ?? []), (int) one('SELECT `blob` IS NULL FROM shared_records WHERE uuid = ?', [$tbs['uuid']])], [200, 2, 1]);

section('profile labels need records');
$r = api($u, 'POST', '/sync', ['profile' => 'p-empty', 'since' => '', 'records' => [], 'name' => 'Ghost']);
check('an empty partition gets no label row', [$r['code'], (int) one('SELECT COUNT(*) FROM sync_profiles WHERE profile = "p-empty"')], [200, 0]);
api($u, 'POST', '/sync', ['profile' => 'ps', 'since' => '', 'records' => [], 'name' => 'Renamed']);
check('a partition with records is renamed', one('SELECT name FROM sync_profiles WHERE user_id = ? AND profile = "ps"', [$u['id']]), 'Renamed');

// ===========================================================================
section('caps (smaller ones set for the test)');
setConfig(['quota' => ['profiles' => 5, 'records' => 300, 'bytes' => 1024 * 1024, 'shares' => 3, 'share_records' => 300, 'share_bytes' => 1024 * 1024]]);
$c = mkuser('carol@stage.test');
$codes = [];
for ($i = 1; $i <= 5; $i++) {
    $codes[] = api($c, 'POST', '/sync', ['profile' => "c$i", 'since' => '', 'records' => [rec('servers', $now)]])['code'];
}
check('5 profiles fit', array_unique($codes), [200]);
$r = api($c, 'POST', '/sync', ['profile' => 'c6', 'since' => '', 'records' => [rec('servers', $now)]]);
check('the 6th is refused', [$r['code'], $r['json']['error'] ?? null], [507, 'quota_exceeded']);
check('the message names the cap', str_contains((string) ($r['json']['message'] ?? ''), '5 per account'), true);
$r = api($c, 'POST', '/sync', ['profile' => 'c6', 'since' => '', 'records' => []]);
check('pulling a new name is still fine', $r['code'], 200);
$r = api($c, 'POST', '/sync', ['profile' => 'c5', 'since' => '', 'records' => [rec('servers', $now)]]);
check('existing profiles still sync', $r['code'], 200);

$dv = mkuser('dave@stage.test');
$tombs = static function (int $n) use ($now): array {
    $out = [];
    for ($i = 0; $i < $n; $i++) {
        $out[] = ['uuid' => bin2hex(random_bytes(16)), 'entity_type' => 'servers', 'updated_at' => stamp($now), 'deleted' => true];
    }
    return $out;
};
$first = $tombs(150);
check('150 rows into d1', api($dv, 'POST', '/sync', ['profile' => 'd1', 'since' => 'z', 'records' => $first])['code'], 200);
check('150 rows into d2', api($dv, 'POST', '/sync', ['profile' => 'd2', 'since' => 'z', 'records' => $tombs(150)])['code'], 200);
$r = api($dv, 'POST', '/sync', ['profile' => 'd1', 'since' => 'z', 'records' => $tombs(1)]);
check('one more row is refused', [$r['code'], $r['json']['error'] ?? null], [507, 'quota_exceeded']);
check('nothing of it was stored', (int) one('SELECT COUNT(*) FROM sync_records WHERE user_id = ?', [$dv['id']]), 300);
$again = $first[0];
$again['updated_at'] = stamp($now + 1);
check('updating a row it already holds still works', api($dv, 'POST', '/sync', ['profile' => 'd1', 'since' => 'z', 'records' => [$again]])['code'], 200);
api($dv, 'POST', '/sync/delete', ['profile' => 'd2']);
check('after deleting a profile there is room again', api($dv, 'POST', '/sync', ['profile' => 'd1', 'since' => 'z', 'records' => $tombs(1)])['code'], 200);

$e = mkuser('erin@stage.test');
$big = [];
$codes = [];
for ($i = 0; $i < 6; $i++) {
    $big[$i] = rec('servers', $now + $i, bin2hex(random_bytes(200000)));
    $codes[] = api($e, 'POST', '/sync', ['profile' => 'pe', 'since' => 'z', 'records' => [$big[$i]]])['code'];
}
check('five 200 KB records fit in 1 MB, the sixth does not', $codes, [200, 200, 200, 200, 200, 507]);
$del = ['uuid' => $big[0]['uuid'], 'entity_type' => 'servers', 'updated_at' => stamp($now + 50), 'deleted' => true];
api($e, 'POST', '/sync', ['profile' => 'pe', 'since' => 'z', 'records' => [$del]]);
check('after a deletion it fits', api($e, 'POST', '/sync', ['profile' => 'pe', 'since' => 'z', 'records' => [$big[5]]])['code'], 200);

$f = mkuser('frank@stage.test');
$codes = [];
$firstShare = '';
for ($i = 1; $i <= 3; $i++) {
    $s = bin2hex(random_bytes(16));
    if ($i === 1) $firstShare = $s;
    $codes[] = api($f, 'POST', '/shares/create', ['share_id' => $s, 'name' => "S$i", 'sealed_dek' => 'ab'])['code'];
}
check('3 shares fit', array_unique($codes), [200]);
$r = api($f, 'POST', '/shares/create', ['share_id' => bin2hex(random_bytes(16)), 'name' => 'S4', 'sealed_dek' => 'ab']);
check('the 4th is refused', [$r['code'], $r['json']['error'] ?? null], [507, 'quota_exceeded']);
check('re-creating one it owns still works', api($f, 'POST', '/shares/create', ['share_id' => $firstShare, 'name' => 'S1 renamed', 'sealed_dek' => 'ab'])['code'], 200);
check('300 share rows', api($f, 'POST', '/shares/sync', ['share_id' => $firstShare, 'since' => 'z', 'records' => $tombs(300)])['code'], 200);
$r = api($f, 'POST', '/shares/sync', ['share_id' => $firstShare, 'since' => 'z', 'records' => [rec('servers', $now)]]);
check('one more share row is refused', [$r['code'], $r['json']['error'] ?? null], [507, 'quota_exceeded']);
check('the full share still pulls', api($f, 'POST', '/shares/sync', ['share_id' => $firstShare, 'since' => 'z', 'records' => []])['code'], 200);
$codes = [];
$s2 = bin2hex(random_bytes(16));
api($f, 'POST', '/shares/delete', ['share_id' => $firstShare]);
api($f, 'POST', '/shares/create', ['share_id' => $s2, 'name' => 'Big', 'sealed_dek' => 'ab']);
for ($i = 0; $i < 6; $i++) {
    $codes[] = api($f, 'POST', '/shares/sync', ['share_id' => $s2, 'since' => 'z', 'records' => [rec('servers', $now + $i, bin2hex(random_bytes(200000)))]])['code'];
}
check('a share holds five 200 KB records, not six', $codes, [200, 200, 200, 200, 200, 507]);
restoreConfig();

// ===========================================================================
section('base path');
setConfig(['base_path' => '/submarine']);
check('/submarine/health', req('GET', '/submarine/health')['code'], 200);
check('/submarine/api/health', req('GET', '/submarine/api/health')['code'], 200);
check('/health outside the base path: 404', req('GET', '/health')['code'], 404);
check('/submarineX/health: 404', req('GET', '/submarineX/health')['code'], 404);
$r = req('POST', '/submarine/auth/login', ['email' => 'alice2@stage.test', 'password' => 'correct horse 1']);
check('signing in under the base path', $r['code'], 200);
restoreConfig();

section('bad settings stop the server, with no details in the answer');
setConfig(['security' => ['token_pepper' => 'short']]);
$r = req('GET', '/health');
check('a short pepper: 500 misconfigured', [$r['code'], $r['json']['error'] ?? null], [500, 'misconfigured']);
check('the answer does not say which setting', str_contains($r['body'], 'pepper'), false);
setConfig(['admin' => ['password_hash' => 'not-a-hash']]);
check('a bad admin hash: 500', req('GET', '/health')['code'], 500);
setConfig(['admin' => ['password_hash' => password_hash('x', PASSWORD_DEFAULT), 'path' => '/sync/admin']]);
check('an admin path under the API: 500', req('GET', '/health')['code'], 500);
restoreConfig();
check('back to normal', req('GET', '/health')['code'], 200);

// ===========================================================================
section('client IP: REMOTE_ADDR unless a trusted proxy says otherwise');
$ipCase = function (string $remote, array $hdrs, array $sec): string {
    foreach (['HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CF_CONNECTING_IP'] as $k) unset($_SERVER[$k]);
    $_SERVER['REMOTE_ADDR'] = $remote;
    foreach ($hdrs as $k => $v) $_SERVER[$k] = $v;
    return \Submarine\Lib\Util::clientIp(['security' => $sec + ['trusted_proxies' => [], 'client_ip_header' => 'X-Forwarded-For']]);
};
check('no proxies: a header is ignored', $ipCase('198.51.100.7', ['HTTP_X_FORWARDED_FOR' => '203.0.113.9'], []), '198.51.100.7');
check('from an untrusted address: ignored', $ipCase('198.51.100.7', ['HTTP_X_FORWARDED_FOR' => '203.0.113.9'], ['trusted_proxies' => ['10.0.0.5']]), '198.51.100.7');
check('from a trusted proxy: the client it names', $ipCase('10.0.0.5', ['HTTP_X_FORWARDED_FOR' => '203.0.113.9'], ['trusted_proxies' => ['10.0.0.5']]), '203.0.113.9');
check('a CIDR range', $ipCase('172.18.0.3', ['HTTP_X_FORWARDED_FOR' => '203.0.113.9'], ['trusted_proxies' => ['172.16.0.0/12']]), '203.0.113.9');
check('a proxy that appends: the client-written left end is not believed',
    $ipCase('10.0.0.5', ['HTTP_X_FORWARDED_FOR' => '1.2.3.4, 203.0.113.9'], ['trusted_proxies' => ['10.0.0.5']]), '203.0.113.9');
check('two proxies: the first address that is not one of ours',
    $ipCase('10.0.0.5', ['HTTP_X_FORWARDED_FOR' => '1.2.3.4, 203.0.113.9, 10.0.0.6'], ['trusted_proxies' => ['10.0.0.0/24']]), '203.0.113.9');
check('a port on the address is dropped', $ipCase('10.0.0.5', ['HTTP_X_FORWARDED_FOR' => '203.0.113.9:4711'], ['trusted_proxies' => ['10.0.0.5']]), '203.0.113.9');
check('IPv6 in brackets', $ipCase('10.0.0.5', ['HTTP_X_FORWARDED_FOR' => '[2001:db8::5]:443'], ['trusted_proxies' => ['10.0.0.5']]), '2001:db8::5');
check('garbage from a trusted proxy: REMOTE_ADDR', $ipCase('10.0.0.5', ['HTTP_X_FORWARDED_FOR' => 'nope'], ['trusted_proxies' => ['10.0.0.5']]), '10.0.0.5');
check('X-Real-IP when that is the header', $ipCase('10.0.0.5', ['HTTP_X_REAL_IP' => '203.0.113.9', 'HTTP_X_FORWARDED_FOR' => '1.1.1.1'], ['trusted_proxies' => ['10.0.0.5'], 'client_ip_header' => 'X-Real-IP']), '203.0.113.9');
check('CF-Connecting-IP when that is the header', $ipCase('10.0.0.5', ['HTTP_CF_CONNECTING_IP' => '2001:db8::7'], ['trusted_proxies' => ['10.0.0.5'], 'client_ip_header' => 'CF-Connecting-IP']), '2001:db8::7');
check('a host name as a proxy', $ipCase('127.0.0.1', ['HTTP_X_FORWARDED_FOR' => '203.0.113.9'], ['trusted_proxies' => ['localhost']]), '203.0.113.9');
check('a host name that does not resolve trusts nobody', $ipCase('127.0.0.1', ['HTTP_X_FORWARDED_FOR' => '203.0.113.9'], ['trusted_proxies' => ['no-such-host.invalid']]), '127.0.0.1');
$_SERVER['REMOTE_ADDR'] = '10.0.0.5';
$_SERVER['HTTP_X_FORWARDED_PROTO'] = 'https';
check('https from a trusted proxy', \Submarine\Lib\Util::isHttps(['security' => ['trusted_proxies' => ['10.0.0.5']]]), true);
check('https header from anyone else is ignored', \Submarine\Lib\Util::isHttps(['security' => ['trusted_proxies' => ['10.0.0.9']]]), false);
$_SERVER['HTTP_X_FORWARDED_PROTO'] = 'https, http';
check('X-Forwarded-Proto: the right-most value counts (here http)', \Submarine\Lib\Util::isHttps(['security' => ['trusted_proxies' => ['10.0.0.5']]]), false);
$_SERVER['HTTP_X_FORWARDED_PROTO'] = 'http, https';
check('... and here https', \Submarine\Lib\Util::isHttps(['security' => ['trusted_proxies' => ['10.0.0.5']]]), true);
unset($_SERVER['HTTP_X_FORWARDED_PROTO']);
check('a host-name proxy is never matched for a public address (no lookup)',
    $ipCase('198.51.100.7', ['HTTP_X_FORWARDED_FOR' => '203.0.113.9'], ['trusted_proxies' => ['localhost']]), '198.51.100.7');

section('the global limit writes one log row per address and window, not one per refused request');
setConfig(['limits' => ['rate_ip_global' => [5, 60]]]);
clearRL();
$pdo->exec("DELETE FROM auth_events WHERE event = 'rate_limited'");
$codes = [];
for ($i = 0; $i < 12; $i++) $codes[] = req('GET', '/health')['code'];
check('5 answered, 7 refused', [count(array_filter($codes, fn ($c) => $c === 200)), count(array_filter($codes, fn ($c) => $c === 429))], [5, 7]);
check('one row in the event log', (int) one("SELECT COUNT(*) FROM auth_events WHERE event = 'rate_limited'"), 1);
restoreConfig();
clearRL();

section('ids compare byte by byte');
$cb = mkuser('case@stage.test');
api($cb, 'POST', '/sync', ['profile' => 'Work', 'since' => '', 'records' => [rec('servers', $now)]]);
$r = api($cb, 'POST', '/sync', ['profile' => 'work', 'since' => '', 'records' => [rec('servers', $now)]]);
check('"Work" and "work" are two profiles', [$r['code'], count($r['json']['records'] ?? []), (int) one('SELECT COUNT(DISTINCT profile) FROM sync_records WHERE user_id = ?', [$cb['id']])], [200, 1, 2]);
$up = rec('servers', $now);
$up['updated_at'] = sprintf('%015d:%05d:%s', $now, 0, 'a');
api($cb, 'POST', '/sync', ['profile' => 'Work', 'since' => '', 'records' => [$up]]);
$older = $up;
$older['updated_at'] = sprintf('%015d:%05d:%s', $now, 0, 'B');
$r = api($cb, 'POST', '/sync', ['profile' => 'Work', 'since' => '', 'records' => [$older]]);
check('stamps that differ only in case order as bytes ("B" < "a"): the older one loses',
    one('SELECT updated_at FROM sync_records WHERE uuid = ?', [$up['uuid']]), $up['updated_at']);

section('client IP on the wire: the rate limits count the right address');
setConfig(['security' => ['trusted_proxies' => ['127.0.0.1']]]);
clearRL();
req('GET', '/health', null, ['X-Forwarded-For' => '203.0.113.77']);
check('counted against the address the proxy names', (int) one("SELECT COUNT(*) FROM rate_limits WHERE bucket = 'global:ip:203.0.113.77'"), 1);
restoreConfig();
clearRL();
req('GET', '/health', null, ['X-Forwarded-For' => '203.0.113.78']);
check('without a trusted proxy the header is ignored', (int) one("SELECT COUNT(*) FROM rate_limits WHERE bucket = 'global:ip:203.0.113.78'"), 0);

section('stamp rule');
$ms = (int) (microtime(true) * 1000);
foreach ([
    ['now', stamp($ms), true],
    ['escrow sentinel', '000000000000000:00000:0', true],
    ['backfill sentinel', '000000000000001:00000:backfill', true],
    ['23 hours ahead', stamp($ms + 23 * 3600000), true],
    ['25 hours ahead', stamp($ms + 25 * 3600000), false],
    ['all nines', '999999999999999:00000:remote', false],
    ['short millis', '1234:00000:node', false],
    ['node with a dash', stamp($ms, 0, 'ab-cd'), false],
    ['trailing newline', stamp($ms) . "\n", false],
] as [$label, $s, $want]) {
    check("stamp: $label", \Submarine\Lib\Util::validSyncStamp($s), $want);
}

done();
