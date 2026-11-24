<?php
// Accounts and sign-in: the lockout without an oracle, the timing floors,
// single-use codes under a race, the newest codes kept, mail after the answer
// and capped, limits, the sharing limits and rules, the sharing key's
// password, account deletion, and the JSON key-flood guard.
//   php tests/auth-test.php
declare(strict_types=1);
require __DIR__ . '/lib.php';

wipe();
$now = (int) (microtime(true) * 1000);
// Mail "on" but to a port nobody listens on: codes are made, sending fails.
$mailOn = ['mail' => ['transport' => 'smtp', 'smtp_host' => '127.0.0.1', 'smtp_port' => 9, 'smtp_security' => 'none', 'from_address' => 'sync@stage.test']];

// ===========================================================================
section('password lockout: no oracle, no endless lock');
setConfig($mailOn);
$lu = mkuser('lock@stage.test', 'right password 1');
$fail = function (string $email, string $pw) { clearRL(); return req('POST', '/auth/login', ['email' => $email, 'password' => $pw]); };
$codes = [];
for ($i = 1; $i <= 4; $i++) $codes[] = $fail('lock@stage.test', "wrong $i")['code'];
check('four wrong passwords', $codes, [401, 401, 401, 401]);
check('not locked yet', one('SELECT locked_until IS NULL FROM users WHERE id = ?', [$lu['id']]), 1);
$r5 = $fail('lock@stage.test', 'wrong 5');
$lock = (int) one('SELECT locked_until FROM users WHERE id = ?', [$lu['id']]);
check('the fifth locks, and the count starts again', [$r5['code'], $lock > time(), (int) one('SELECT failed_login_count FROM users WHERE id = ?', [$lu['id']])], [401, true, 0]);
$right = $fail('lock@stage.test', 'right password 1');
check('while locked the right password gets the same answer as a wrong one', [$right['code'], $right['body']], [401, $r5['body']]);
sleep(1);
$fail('lock@stage.test', 'wrong 6');
check('a try while locked neither counts nor stretches the lock',
    [(int) one('SELECT locked_until FROM users WHERE id = ?', [$lu['id']]), (int) one('SELECT failed_login_count FROM users WHERE id = ?', [$lu['id']])], [$lock, 0]);
mkpending('pending@stage.test');
$bodies = [
    'no such account' => $fail('nobody@stage.test', 'whatever 1')['body'],
    'no password yet' => $fail('pending@stage.test', 'whatever 1')['body'],
    'locked, right pw' => $right['body'],
    'wrong password'  => $r5['body'],
];
check('one answer for every failure', count(array_unique($bodies)), 1);
check('with mail on, it says signing in by email works', str_contains((string) json_decode($r5['body'], true)['message'], 'signing in by email still works'), true);
clearRL();
$r = req('POST', '/auth/request-login', ['email' => 'lock@stage.test']);
check('a sign-in code is made while locked', [$r['code'], (int) one('SELECT COUNT(*) FROM verify_tokens WHERE user_id = ? AND purpose = "login"', [$lu['id']])], [200, 1]);
$code = mktoken($lu['id'], 'login');
$r = req('POST', '/auth/login-with-link', ['login_token' => $code]);
check('the code signs in while locked', [$r['code'], strlen((string) ($r['json']['token'] ?? ''))], [200, 64]);
check('and ends the lock', [one('SELECT locked_until IS NULL FROM users WHERE id = ?', [$lu['id']]), (int) one('SELECT failed_login_count FROM users WHERE id = ?', [$lu['id']])], [1, 0]);
check('the password works again', $fail('lock@stage.test', 'right password 1')['code'], 200);
$pdo->prepare('UPDATE users SET locked_until = ?, failed_login_count = 0 WHERE id = ?')->execute([time() - 1, $lu['id']]);
$fail('lock@stage.test', 'wrong 7');
check('after a lock runs out, one wrong try is just one', [(int) one('SELECT failed_login_count FROM users WHERE id = ?', [$lu['id']]), (int) one('SELECT locked_until > UNIX_TIMESTAMP() FROM users WHERE id = ?', [$lu['id']])], [1, 0]);
restoreConfig();
$r = $fail('lock@stage.test', 'wrong 8');
check('with mail off, it points to the admin instead', str_contains((string) ($r['json']['message'] ?? ''), "admin can make you a reset code"), true);
clearRL();
req('POST', '/auth/request-login', ['email' => 'lock@stage.test']);
check('with mail off, no sign-in code is made at all', (int) one('SELECT COUNT(*) FROM verify_tokens WHERE user_id = ? AND purpose = "login" AND used_at IS NULL', [$lu['id']]), 1);

section('every failed sign-in leaves at the same moment');
// A floor well above one password check even on a busy test machine; the
// default (1000 ms) is for a server that does nothing else.
setConfig(['limits' => ['login_fail_floor_ms' => 1600]]);
$t =['no such account' => [], 'wrong password' => [], 'old cost-10 hash' => [], 'locked' => [], 'no password yet' => []];
$pdo->prepare('UPDATE users SET locked_until = ? WHERE id = ?')->execute([time() + 600, $lu['id']]);
$wu = mkuser('timing@stage.test', 'right password 2');
$w10 = mkuser('timing10@stage.test', 'right password 3', ['cost' => 10]);
for ($i = 0; $i < 4; $i++) {
    $pdo->prepare('UPDATE users SET password_hash = ? WHERE id = ?')->execute([password_hash('right password 3', PASSWORD_BCRYPT, ['cost' => 10]), $w10['id']]);
    $t['no such account'][]  = $fail("ghost$i@stage.test", 'x pw 123')['ms'];
    $t['wrong password'][]   = $fail('timing@stage.test', "x pw $i")['ms'];
    $t['old cost-10 hash'][] = $fail('timing10@stage.test', "x pw $i")['ms'];
    $t['locked'][]           = $fail('lock@stage.test', 'x pw 123')['ms'];
    $t['no password yet'][]  = $fail('pending@stage.test', 'x pw 123')['ms'];
    $pdo->prepare('UPDATE users SET failed_login_count = 0, locked_until = NULL WHERE id IN (?, ?)')->execute([$wu['id'], $w10['id']]);
}
$med = [];
foreach ($t as $k => $v) { sort($v); $med[$k] = $v[1]; echo "      median ms, $k: {$v[1]} (all: " . implode(' ', $v) . ")\n"; }
$floor = (int) $cfg['limits']['login_fail_floor_ms'];
check("no failed sign-in answers before $floor ms", min(array_map('min', $t)) >= $floor - 5, true);
check('all kinds of failure take the same time (medians within 80 ms)', max($med) - min($med) <= 80, true);
restoreConfig();
check('the dummy hash has the cost new hashes get here', password_get_info(\Submarine\Lib\Auth::dummyHash())['options']['cost'] ?? null,
    password_get_info(password_hash('x', PASSWORD_DEFAULT))['options']['cost'] ?? null);

section('old password hashes are redone at today\'s cost');
$old = mkuser('oldhash@stage.test', 'old hash pass 1', ['cost' => 10]);
$want = '$2y$' . sprintf('%02d', password_get_info(password_hash('x', PASSWORD_DEFAULT))['options']['cost'] ?? 12) . '$';
check('a cost-10 hash is redone at sign-in', [strlen($old['tok']), substr((string) one('SELECT password_hash FROM users WHERE id = ?', [$old['id']]), 0, 7)], [64, $want]);
clearRL();
check('and the password still works', req('POST', '/auth/login', ['email' => 'oldhash@stage.test', 'password' => 'old hash pass 1'])['code'], 200);

// ===========================================================================
section('single-use codes stay single-use under a race');
$ru = mkuser('race@stage.test');
$c1 = mktoken($ru['id'], 'login');
check('8 sign-ins with one code at once: one wins', race(8, 'POST', '/auth/login-with-link', ['login_token' => $c1]), [200, 400, 400, 400, 400, 400, 400, 400]);
$c2 = mktoken($ru['id'], 'reset');
check('8 resets with one code at once: one wins', race(8, 'POST', '/auth/reset-with-token', ['reset_token' => $c2, 'password' => 'new password 9']), [200, 400, 400, 400, 400, 400, 400, 400]);
$vid = mkpending('race-verify@stage.test');
$c3 = mktoken($vid, 'verify');
clearRL();
check('8 verifications with one code at once: one wins', race(8, 'POST', '/auth/verify', ['token' => $c3]), [200, 400, 400, 400, 400, 400, 400, 400]);
$c4 = mktoken($vid, 'claim');
check('8 password settings with one claim at once: one wins', race(8, 'POST', '/auth/set-password', ['claim_token' => $c4, 'password' => 'first password 1']), [200, 400, 400, 400, 400, 400, 400, 400]);
check('sign-in tokens issued: one per code', (int) one('SELECT COUNT(*) FROM auth_tokens WHERE user_id = ?', [$vid]), 1);

section('POST /auth/verify, GET still works');
$pv = mkpending('verify-post@stage.test');
$tok = mktoken($pv, 'verify');
clearRL();
$r = req('POST', '/auth/verify', ['token' => $tok]);
check('POST with the code in the body', [$r['code'], strlen((string) ($r['json']['claim_token'] ?? '')), $r['json']['email'] ?? null], [200, 48, 'verify-post@stage.test']);
$r = req('GET', '/auth/verify?token=' . $tok);
check('the same code again (GET) is refused', [$r['code'], $r['json']['error'] ?? null], [400, 'verify_failed']);
$r = req('GET', '/auth/verify?token=' . mktoken($pv, 'verify'));
check('GET with a fresh code, as the released apps do', $r['code'], 200);
$r = req('POST', '/auth/verify', []);
check('POST without a code', [$r['code'], $r['json']['error'] ?? null], [400, 'missing_token']);
$exp = mktoken($pv, 'verify', -5);
check('an expired code', req('GET', '/auth/verify?token=' . $exp)['code'], 400);

section('"check your inbox" answers all leave at 400 ms');
setConfig($mailOn + ['signup' => 'open']);
$ma = ['unknown address' => [], 'registered address' => [], 'malformed address' => []];
for ($i = 0; $i < 3; $i++) {
    clearRL();
    $ma['unknown address'][]    = req('POST', '/auth/request-reset', ['email' => "nobody$i@stage.test"])['ms'];
    $ma['registered address'][] = req('POST', '/auth/request-reset', ['email' => 'timing@stage.test'])['ms'];
    $ma['malformed address'][]  = req('POST', '/auth/request-reset', ['email' => 'not-an-email'])['ms'];
    clearRL();
    $ma['unknown address'][]    = req('POST', '/auth/request-login', ['email' => "nobody$i@stage.test"])['ms'];
    $ma['registered address'][] = req('POST', '/auth/request-login', ['email' => 'timing@stage.test'])['ms'];
    clearRL();
    $ma['unknown address'][]    = req('POST', '/auth/signup', ['email' => "fresh$i@stage.test"])['ms'];
    $ma['registered address'][] = req('POST', '/auth/signup', ['email' => 'timing@stage.test'])['ms'];
}
$med = [];
foreach ($ma as $k => $v) { sort($v); $med[$k] = $v[intdiv(count($v), 2)]; echo "      median ms, $k: {$med[$k]} (all: " . implode(' ', $v) . ")\n"; }
check('none answers before 400 ms', min(array_map('min', $ma)) >= 395, true);
check('registered or not, the same time (medians within 80 ms)', max($med) - min($med) <= 80, true);

section('the last three codes stay valid');
$ku = mkuser('keep@stage.test');
for ($i = 0; $i < 4; $i++) { clearRL(); req('POST', '/auth/request-login', ['email' => 'keep@stage.test']); }
check('four sign-in codes asked for: three are kept', (int) one('SELECT COUNT(*) FROM verify_tokens WHERE user_id = ? AND purpose = "login"', [$ku['id']]), 3);
for ($i = 0; $i < 4; $i++) { clearRL(); req('POST', '/auth/request-reset', ['email' => 'keep@stage.test']); }
check('four reset codes asked for: three are kept', (int) one('SELECT COUNT(*) FROM verify_tokens WHERE user_id = ? AND purpose = "reset"', [$ku['id']]), 3);
$used = mktoken($ku['id'], 'login');
req('POST', '/auth/login-with-link', ['login_token' => $used]);
clearRL();
req('POST', '/auth/request-login', ['email' => 'keep@stage.test']);
check('a used code is never one of the kept ones', (int) one('SELECT COUNT(*) FROM verify_tokens WHERE user_id = ? AND purpose = "login" AND used_at IS NULL', [$ku['id']]), 3);

section('mail goes out after the answer, under an hourly cap; sign-ups get half of it');
// per_hour 4: sign-up codes may use 2, and the rest stays for real accounts.
$mo = mkuser('mailcap-owner@stage.test');
setConfig(array_replace_recursive($mailOn, ['signup' => 'open', 'mail' => ['per_hour' => 4]]));
$mailRows = fn (string $email): int => (int) one('SELECT COUNT(*) FROM auth_events WHERE event IN ("mail_failed", "mail_suppressed") AND email = ?', [$email]);
$kindsOf = fn (string $like): array => array_map(fn ($k) => [$k['event'], (int) $k['n']],
    rows('SELECT event, COUNT(*) n FROM auth_events WHERE event IN ("mail_failed", "mail_suppressed") AND email LIKE ? GROUP BY event ORDER BY event', [$like]));
$answers = [];
for ($i = 1; $i <= 3; $i++) {
    $r = req('POST', '/auth/signup', ['email' => "mailcap$i@stage.test"]);
    $answers[] = [$r['code'], $r['json']['status'] ?? null, $r['ms'] < 2000];
    // The mail, and its count, come after the answer.
    waitFor(fn () => $mailRows("mailcap$i@stage.test"), 30);
}
check('three signups answered at once', $answers, [[200, 'pending', true], [200, 'pending', true], [200, 'pending', true]]);
check('two tried (nobody listens, so they fail), the third held back: sign-ups get half', $kindsOf('mailcap_@stage.test'),
    [['mail_failed', 2], ['mail_suppressed', 1]]);
check('the held-back sign-up made no account and no code', (int) one('SELECT COUNT(*) FROM users WHERE email = ?', ['mailcap3@stage.test']), 0);
req('POST', '/auth/request-reset', ['email' => 'mailcap-owner@stage.test']);
waitFor(fn () => $mailRows('mailcap-owner@stage.test') >= 1 ? 1 : 0, 30);
req('POST', '/auth/request-login', ['email' => 'mailcap-owner@stage.test']);
waitFor(fn () => $mailRows('mailcap-owner@stage.test') >= 2 ? 1 : 0, 30);
check('an account still gets its reset and sign-in codes after the sign-ups', [$kindsOf('mailcap-owner@stage.test'),
    (int) one('SELECT COUNT(*) FROM verify_tokens WHERE user_id = ? AND purpose IN ("reset", "login")', [$mo['id']])], [[['mail_failed', 2]], 2]);
// The hour's 4 mails are gone now.
$codesBefore = rows('SELECT token_hash FROM verify_tokens WHERE user_id = ? ORDER BY token_hash', [$mo['id']]);
for ($i = 0; $i < 3; $i++) req('POST', '/auth/request-login', ['email' => 'mailcap-owner@stage.test']);
check('a spent hour makes no new codes, and keeps the ones already sent', rows('SELECT token_hash FROM verify_tokens WHERE user_id = ? ORDER BY token_hash', [$mo['id']]), $codesBefore);
check('each of those is logged as held back', (int) one('SELECT COUNT(*) FROM auth_events WHERE event = "mail_suppressed" AND email = ? AND detail = "login_link"', ['mailcap-owner@stage.test']), 3);
restoreConfig();

section('sign-ups at one moment can\'t spend the part of the hour kept for accounts');
// They all pass the budget check before any mail is counted; the ones past
// the sign-up half must not use up the shared budget on their way out.
$bo = mkuser('burst-owner@stage.test');
setConfig(array_replace_recursive($mailOn, ['signup' => 'open', 'mail' => ['per_hour' => 4]]));
clearRL();
check('five sign-ups at once are answered', race(5, 'POST', '/auth/signup', fn (int $i) => ['email' => "burst$i@stage.test"]), [200, 200, 200, 200, 200]);
waitFor(fn () => count(array_filter(range(0, 4), fn ($i) => $mailRows("burst$i@stage.test") > 0)) === 5 ? 1 : 0, 30);
check('two tried, three held back', $kindsOf('burst_@stage.test'), [['mail_failed', 2], ['mail_suppressed', 3]]);
req('POST', '/auth/request-reset', ['email' => 'burst-owner@stage.test']);
waitFor(fn () => $mailRows('burst-owner@stage.test') >= 1 ? 1 : 0, 30);
req('POST', '/auth/request-login', ['email' => 'burst-owner@stage.test']);
waitFor(fn () => $mailRows('burst-owner@stage.test') >= 2 ? 1 : 0, 30);
check('the account still gets both its codes', $kindsOf('burst-owner@stage.test'), [['mail_failed', 2]]);
restoreConfig();

section('sign-ups at one moment don\'t deadlock');
setConfig($mailOn + ['signup' => 'open']);
for ($i = 0; $i < 5; $i++) mktoken(mkpending("again$i@stage.test"), 'verify');
clearRL();
check('five repeat sign-ups (accounts side by side) at once: all answered',
    race(5, 'POST', '/auth/signup', fn (int $i) => ['email' => "again$i@stage.test"]), [200, 200, 200, 200, 200]);
check('each has one code, the new one', (int) one('SELECT COUNT(*) FROM verify_tokens v JOIN users u ON u.id = v.user_id
    WHERE u.email LIKE "again_@stage.test" AND v.purpose = "verify"'), 5);
clearRL();
check('one new address three times at once: all answered', race(3, 'POST', '/auth/signup', ['email' => 'same-moment@stage.test']), [200, 200, 200]);
check('one account, one code', [(int) one('SELECT COUNT(*) FROM users WHERE email = ?', ['same-moment@stage.test']),
    (int) one('SELECT COUNT(*) FROM verify_tokens v JOIN users u ON u.id = v.user_id WHERE u.email = ? AND v.purpose = "verify"', ['same-moment@stage.test'])], [1, 1]);
restoreConfig();

section('limits and their answers');
setConfig($mailOn + ['signup' => 'open']);
$codes = [];
for ($i = 1; $i <= 6; $i++) $codes[] = req('POST', '/auth/signup', ['email' => "flood$i@stage.test"]);
$last = end($codes);
check('the sixth signup from one address is limited', [$last['code'], $last['json']['error'] ?? null], [429, 'rate_limited']);
check('the answer names no bucket', $last['json']['message'] ?? null, 'Too many requests, slow down');
check('Retry-After is sent', header_of($last, 'Retry-After') !== null, true);
clearRL();
check('ten sign-ups from one address at once: exactly five pass', race(10, 'POST', '/auth/signup', fn (int $i) => ['email' => "at-once$i@stage.test"]),
    [200, 200, 200, 200, 200, 429, 429, 429, 429, 429]);
restoreConfig();
foreach ([
    ['2001:db8:1:2:3:4:5:6', '2001:db8:1:2::/64'],
    ['2001:db8:1:2:ffff:ffff:ffff:ffff', '2001:db8:1:2::/64'],
    ['2001:db8::1', '2001:db8::/64'],
    ['::ffff:198.51.100.7', '198.51.100.7'],
    ['198.51.100.7', '198.51.100.7'],
    ['not an ip', 'not an ip'],
] as [$in, $want]) {
    check("rate key of $in", \Submarine\Lib\Util::rateKeyIp($in), $want);
}

$long = 'u@' . str_repeat('b', 60) . '.' . str_repeat('c', 60) . '.' . str_repeat('d', 55) . '.com';
setConfig($mailOn + ['signup' => 'open']);
foreach (['/auth/signup', '/auth/login', '/auth/request-reset', '/auth/request-login'] as $path) {
    clearRL();
    $r = req('POST', $path, ['email' => $long, 'password' => 'correct horse 1']);
    check("the longest email the API takes, $path: no 500", $r['code'] < 500, true);
}
restoreConfig();
clearRL();
req('POST', '/auth/login', ['email' => $long, 'password' => 'x']);
check('and its attempts are counted (the bucket row exists)', (int) one("SELECT COUNT(*) FROM rate_limits WHERE bucket LIKE 'login:email:u@bbbb%'") >= 1, true);

// ===========================================================================
section('sharing: lookups and invites per hour; re-sealing a share stays free');
$q = mkuser('owner-q@stage.test');
$p = mkuser('invitee-p@stage.test');
$x = mkuser('stranger-x@stage.test');
foreach ([$p, $x] as $u) {
    api($u, 'POST', '/keys/publish', ['public_key' => bin2hex(random_bytes(32)), 'wrapped_privkey' => 'ab', 'enc_salt' => 'cd']);
}
$s0 = bin2hex(random_bytes(16));
api($q, 'POST', '/shares/create', ['share_id' => $s0, 'name' => 'Zero', 'sealed_dek' => 'ab']);
api($q, 'POST', '/shares/invite', ['share_id' => $s0, 'email' => 'invitee-p@stage.test', 'role' => 'editor', 'sealed_dek' => 'ab']);
clearRL();
$codes = [];
for ($i = 1; $i <= 60; $i++) $codes[] = api($q, 'POST', '/keys/lookup', ['email' => 'stranger-x@stage.test'])['code'];
check('60 lookups of a stranger in an hour', array_unique($codes), [200]);
$r = api($q, 'POST', '/keys/lookup', ['email' => 'stranger-x@stage.test']);
check('the 61st is limited', [$r['code'], $r['json']['error'] ?? null], [429, 'rate_limited']);
check('so is one for an unknown address', api($q, 'POST', '/keys/lookup', ['email' => 'unknown-addr@stage.test'])['code'], 429);
$r = api($q, 'POST', '/keys/lookup', ['email' => 'invitee-p@stage.test']);
check('someone on a profile it shares is still looked up', [$r['code'], $r['json']['user_id'] ?? null], [200, $p['id']]);
for ($i = 1; $i <= 61; $i++) {
    $pdo->prepare('INSERT INTO users (email, password_hash, status) VALUES (?, "x", "active")')->execute(["inv$i@stage.test"]);
}
clearRL();
$codes = [];
for ($i = 1; $i <= 60; $i++) {
    $codes[] = api($q, 'POST', '/shares/invite', ['share_id' => $s0, 'email' => "inv$i@stage.test", 'role' => 'user', 'sealed_dek' => 'ab'])['code'];
}
check('60 new people invited in an hour', array_unique($codes), [200]);
$r = api($q, 'POST', '/shares/invite', ['share_id' => $s0, 'email' => 'inv61@stage.test', 'role' => 'user', 'sealed_dek' => 'ab']);
check('the 61st is limited', [$r['code'], $r['json']['error'] ?? null], [429, 'rate_limited']);
$codes = [];
foreach (['invitee-p@stage.test', 'inv1@stage.test', 'inv2@stage.test', 'inv60@stage.test'] as $em) {
    $codes[] = api($q, 'POST', '/shares/invite', ['share_id' => $s0, 'email' => $em, 'role' => 'user', 'sealed_dek' => 'cd'])['code'];
}
check('re-sealing for members already on the share still works', array_unique($codes), [200]);
check('their grants were replaced', (int) one('SELECT COUNT(*) FROM profile_members WHERE share_id = ? AND sealed_dek = "cd"', [$s0]), 4);

section('sharing: at most 50 invites waiting for one person');
setConfig(['quota' => ['shares' => 100]]);
clearRL();
$ids = [$s0];
for ($i = 1; $i <= 49; $i++) {
    $s = bin2hex(random_bytes(16));
    $ids[] = $s;
    api($q, 'POST', '/shares/create', ['share_id' => $s, 'name' => "S$i", 'sealed_dek' => 'ab']);
    api($q, 'POST', '/shares/invite', ['share_id' => $s, 'email' => 'invitee-p@stage.test', 'role' => 'user', 'sealed_dek' => 'ab']);
}
check('50 invites waiting', (int) one('SELECT COUNT(*) FROM profile_members WHERE member_user_id = ? AND status = "pending"', [$p['id']]), 50);
$o2 = mkuser('owner-r@stage.test');
$s51 = bin2hex(random_bytes(16));
api($o2, 'POST', '/shares/create', ['share_id' => $s51, 'name' => 'R', 'sealed_dek' => 'ab']);
$r = api($o2, 'POST', '/shares/invite', ['share_id' => $s51, 'email' => 'invitee-p@stage.test', 'role' => 'user', 'sealed_dek' => 'ab']);
check('a 51st is refused', [$r['code'], $r['json']['error'] ?? null], [429, 'too_many_pending']);
clearRL();
check('re-inviting to a share already waiting still works',
    api($q, 'POST', '/shares/invite', ['share_id' => $ids[3], 'email' => 'invitee-p@stage.test', 'role' => 'editor', 'sealed_dek' => 'ab'])['code'], 200);
restoreConfig();

section('sharing: the key only after accepting');
$r = api($p, 'POST', '/shares/dek', ['share_id' => $ids[5]]);
check('a waiting invitee gets no key', [$r['code'], $r['json']['error'] ?? null], [403, 'forbidden']);
$r = api($p, 'POST', '/shares/members', ['share_id' => $ids[5]]);
check('nor the member list', [$r['code'], $r['json']['error'] ?? null], [403, 'forbidden']);
$r = api($p, 'POST', '/shares/accept', ['share_id' => $ids[5]]);
check('accepting answers with the key', [$r['code'], $r['json']['sealed_dek'] ?? null], [200, 'ab']);
$r = api($p, 'POST', '/shares/dek', ['share_id' => $ids[5]]);
check('then the key is there', [$r['code'], $r['json']['status'] ?? null], [200, 'active']);
check('and the member list', api($p, 'POST', '/shares/members', ['share_id' => $ids[5]])['code'], 200);
$r = api($x, 'POST', '/shares/members', ['share_id' => $ids[5]]);
check('a stranger can not list the members', $r['code'], 403);
$r = api($p, 'POST', '/shares/invite', ['share_id' => $ids[5], 'email' => 'stranger-x@stage.test', 'role' => 'user', 'sealed_dek' => 'ab']);
check('a member who is not the owner can not invite', $r['code'], 403);
$r = api($p, 'POST', '/shares/delete', ['share_id' => $ids[5]]);
check('nor delete the share', $r['code'], 403);

section('sharing: names');
clearRL();
$sn = bin2hex(random_bytes(16));
$o3 = mkuser('names@stage.test');
$r = api($o3, 'POST', '/shares/create', ['share_id' => $sn, 'name' => "Team\u{202E}gpj.exe\tA\u{200C}B", 'sealed_dek' => 'ab']);
check('direction and control characters taken out, ZWNJ kept', [$r['code'], one('SELECT name FROM shared_profiles WHERE share_id = ?', [$sn])], [200, "Teamgpj.exeA\u{200C}B"]);
$r = api($o3, 'POST', '/shares/create', ['share_id' => bin2hex(random_bytes(16)), 'name' => "\u{202E}\u{2066}", 'sealed_dek' => 'ab']);
check('a name of nothing but those is refused', $r['code'], 400);
$r = api($o3, 'POST', '/shares/create', ['share_id' => bin2hex(random_bytes(16)), 'name' => 'Équipe ネットワーク', 'sealed_dek' => 'ab']);
check('a name in other scripts is fine', $r['code'], 200);

section('sharing: a deleted share id stays deleted');
$sd = $ids[7];
api($p, 'POST', '/shares/accept', ['share_id' => $sd]);
api($q, 'POST', '/shares/sync', ['share_id' => $sd, 'since' => '', 'records' => [rec('servers', $now)]]);
$r = api($q, 'POST', '/shares/delete', ['share_id' => $sd]);
check('the owner deletes it', [$r['code'], (int) one('SELECT COUNT(*) FROM deleted_shares WHERE share_id = ?', [$sd])], [200, 1]);
$r = api($q, 'POST', '/shares/create', ['share_id' => $sd, 'name' => 'Again', 'sealed_dek' => 'ab']);
check('the owner can not register that id again', [$r['code'], $r['json']['error'] ?? null], [410, 'share_deleted']);
$r = api($p, 'POST', '/shares/create', ['share_id' => $sd, 'name' => 'Mine now', 'sealed_dek' => 'ab']);
check('nor can a former member', [$r['code'], $r['json']['error'] ?? null], [410, 'share_deleted']);
$r = api($p, 'POST', '/shares/sync', ['share_id' => $sd, 'since' => '', 'records' => []]);
check('a former member\'s sync hears it was deleted', [$r['code'], $r['json']['error'] ?? null], [410, 'share_deleted']);
$r = api($p, 'POST', '/shares/dek', ['share_id' => $sd]);
check('and so does a key request', [$r['code'], $r['json']['error'] ?? null], [410, 'share_deleted']);
check('a share that never existed is still just forbidden', api($p, 'POST', '/shares/dek', ['share_id' => bin2hex(random_bytes(16))])['code'], 403);

// ===========================================================================
section('replacing a published sharing key takes the account password');
$v = mkuser('keys@stage.test', 'right password 7');
$key = fn () => ['public_key' => bin2hex(random_bytes(32)), 'wrapped_privkey' => bin2hex(random_bytes(48)), 'enc_salt' => bin2hex(random_bytes(16))];
$k1 = $key();
$r = api($v, 'POST', '/keys/publish', $k1);
check('the first publish needs only the token', [$r['code'], $r['json']['created'] ?? null], [200, true]);
$r = api($v, 'POST', '/keys/publish', $k1);
check('the same key again (a retry) is fine', [$r['code'], $r['json']['created'] ?? null, $r['json']['rotated'] ?? null], [200, false, false]);
$k2 = $key();
$r = api($v, 'POST', '/keys/publish', $k2);
check('a new key with no password: 403 reauth_required', [$r['code'], $r['json']['error'] ?? null], [403, 'reauth_required']);
check('and the published key is still the first', one('SELECT public_key FROM user_keys WHERE user_id = ?', [$v['id']]), $k1['public_key']);
$r = api($v, 'POST', '/keys/publish', $k2 + ['current_password' => 'wrong password']);
check('a wrong password: 403', [$r['code'], $r['json']['error'] ?? null], [403, 'reauth_required']);
check('and it counts as a failed login', (int) one('SELECT failed_login_count FROM users WHERE id = ?', [$v['id']]) >= 1, true);
$r = api($v, 'POST', '/keys/publish', $k2 + ['current_password' => 'right password 7']);
check('the right password: the key is replaced', [$r['code'], $r['json']['rotated'] ?? null], [200, true]);
$pdo->prepare('UPDATE users SET locked_until = ? WHERE id = ?')->execute([time() + 600, $v['id']]);
$r = api($v, 'POST', '/keys/publish', $key() + ['current_password' => 'right password 7']);
check('a locked account is refused, even with the right password', [$r['code'], $r['json']['error'] ?? null], [403, 'reauth_required']);
$pdo->prepare('UPDATE users SET locked_until = NULL, failed_login_count = 0 WHERE id = ?')->execute([$v['id']]);
$bad = $key();
$bad['public_key'] .= "\n";
check('a public key with a trailing newline is refused', api($v, 'POST', '/keys/publish', $bad + ['current_password' => 'right password 7'])['code'], 400);

section('the first sharing key');
$key = fn () => ['public_key' => bin2hex(random_bytes(32)), 'wrapped_privkey' => bin2hex(random_bytes(48)), 'enc_salt' => bin2hex(random_bytes(16))];
$f1 = mkuser('firstkey1@stage.test', 'first key pass 1');
$r = api($f1, 'POST', '/keys/publish', $key() + ['current_password' => 'wrong one']);
check('when the app sends a password, it must be right', [$r['code'], $r['json']['error'] ?? null, (int) one('SELECT COUNT(*) FROM user_keys WHERE user_id = ?', [$f1['id']])], [403, 'reauth_required', 0]);
$r = api($f1, 'POST', '/keys/publish', $key() + ['current_password' => 'first key pass 1']);
check('with the right one: set up', [$r['code'], $r['json']['created'] ?? null], [200, true]);
$f2 = mkuser('firstkey2@stage.test');
$r = api($f2, 'POST', '/keys/publish', $key());
check('without one (released apps): set up, as before', [$r['code'], $r['json']['created'] ?? null], [200, true]);
setConfig(['security' => ['keys_need_password' => true]]);
$f3 = mkuser('firstkey3@stage.test', 'first key pass 3');
$r = api($f3, 'POST', '/keys/publish', $key());
check('keys_need_password: a token alone is refused', [$r['code'], $r['json']['error'] ?? null], [403, 'reauth_required']);
$r = api($f3, 'POST', '/keys/publish', $key() + ['current_password' => 'first key pass 3']);
check('keys_need_password: with the password, set up', $r['code'], 200);
restoreConfig();
$f4 = mkuser('firstkey4@stage.test');
$k4 = $key();
$codes = [];
$mh = curl_multi_init();
$hs = [];
for ($i = 0; $i < 6; $i++) {
    $ch = curl_init(BASE . '/keys/publish');
    curl_setopt_array($ch, [CURLOPT_POST => true, CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => ['Content-Type: application/json', 'X-Auth-Token: ' . $f4['tok']],
        CURLOPT_POSTFIELDS => json_encode($i === 0 ? $k4 : $key())]);
    curl_multi_add_handle($mh, $ch);
    $hs[] = $ch;
}
do { curl_multi_exec($mh, $running); if ($running) curl_multi_select($mh, 1.0); } while ($running);
foreach ($hs as $ch) $codes[] = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
sort($codes);
check('six first keys at once: one is set up, the others need the password', [$codes[0], count(array_filter($codes, fn ($c) => $c === 200)) <= 1], [200, true]);
check('exactly one key is stored', (int) one('SELECT COUNT(*) FROM user_keys WHERE user_id = ?', [$f4['id']]), 1);

section('the sharing key password: 5 tries an hour per account');
$kp = mkuser('keycap@stage.test', 'key cap pass 1');
api($kp, 'POST', '/keys/publish', $key());
$codes = [];
for ($i = 0; $i < 6; $i++) {
    $codes[] = api($kp, 'POST', '/keys/publish', $key() + ['current_password' => "wrong $i"])['code'];
    $pdo->prepare('UPDATE users SET failed_login_count = 0, locked_until = NULL WHERE id = ?')->execute([$kp['id']]);
}
check('five checked, the sixth limited before any check', $codes, [403, 403, 403, 403, 403, 429]);

section('quotas hold under parallel pushes to different profiles');
setConfig(['quota' => ['bytes' => 1024 * 1024, 'profiles' => 4]]);
$parallel = function (array $u, array $bodies): array {
    $mh = curl_multi_init();
    $hs = [];
    foreach ($bodies as $b) {
        $ch = curl_init(BASE . '/sync');
        curl_setopt_array($ch, [CURLOPT_POST => true, CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 60,
            CURLOPT_HTTPHEADER => ['Content-Type: application/json', 'X-Auth-Token: ' . $u['tok']], CURLOPT_POSTFIELDS => json_encode($b)]);
        curl_multi_add_handle($mh, $ch);
        $hs[] = $ch;
    }
    do { curl_multi_exec($mh, $running); if ($running) curl_multi_select($mh, 1.0); } while ($running);
    $codes = array_map(fn ($ch) => curl_getinfo($ch, CURLINFO_RESPONSE_CODE), $hs);
    sort($codes);
    return $codes;
};
$qu = mkuser('race-quota@stage.test');
$bodies = [];
for ($i = 0; $i < 4; $i++) {
    $bodies[] = ['profile' => "q$i", 'since' => '', 'records' => [rec('servers', $now + $i, bin2hex(random_bytes(400000)))]];
}
$codes = $parallel($qu, $bodies);
$bytes = intdiv((int) one('SELECT COALESCE(SUM(LENGTH(`blob`)), 0) FROM sync_records WHERE user_id = ?', [$qu['id']]), 2);
check('four 400 KB pushes at once into a 1 MB quota: two fit', [count(array_filter($codes, fn ($c) => $c === 200)), $bytes <= 1024 * 1024], [2, true]);
$pc = mkuser('race-profiles@stage.test');
$bodies = [];
for ($i = 0; $i < 10; $i++) $bodies[] = ['profile' => "p$i", 'since' => '', 'records' => [rec('servers', $now)]];
$parallel($pc, $bodies);
$held = (int) one('SELECT COUNT(*) FROM (SELECT profile FROM sync_records WHERE user_id = ? UNION SELECT profile FROM sync_revs WHERE user_id = ?) h', [$pc['id'], $pc['id']]);
check('ten new profiles at once with a cap of 4: 4 held', $held, 4);
$r = api($pc, 'POST', '/sync', ['profile' => 'p-late', 'since' => '', 'records' => [rec('servers', $now)]]);
check('and the next one is still refused', $r['code'], 507);
restoreConfig();

section('two accounts creating the same share id at once: one owner');
$o1 = mkuser('race-owner1@stage.test');
$o2 = mkuser('race-owner2@stage.test');
$sidR = bin2hex(random_bytes(16));
$mh = curl_multi_init();
$hs = [];
for ($i = 0; $i < 8; $i++) {
    $u = $i % 2 ? $o2 : $o1;
    $ch = curl_init(BASE . '/shares/create');
    curl_setopt_array($ch, [CURLOPT_POST => true, CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => ['Content-Type: application/json', 'X-Auth-Token: ' . $u['tok']],
        CURLOPT_POSTFIELDS => json_encode(['share_id' => $sidR, 'name' => "N$i", 'sealed_dek' => 'ab'])]);
    curl_multi_add_handle($mh, $ch);
    $hs[] = $ch;
}
do { curl_multi_exec($mh, $running); if ($running) curl_multi_select($mh, 1.0); } while ($running);
$owner = (int) one('SELECT owner_user_id FROM shared_profiles WHERE share_id = ?', [$sidR]);
check('one owner row, and only that account is an owner member',
    [(int) one('SELECT COUNT(*) FROM profile_members WHERE share_id = ? AND role = "owner"', [$sidR]),
     (int) one('SELECT member_user_id FROM profile_members WHERE share_id = ? AND role = "owner"', [$sidR]) === $owner], [1, true]);

section('an account deleted while its request waits for the account lock: 401, nothing left');
/** Start a request without waiting for it; returns [multi handle, curl handle]. */
function startRequest(string $path, array $body, string $tok): array
{
    $mh = curl_multi_init();
    $ch = curl_init(BASE . $path);
    curl_setopt_array($ch, [CURLOPT_POST => true, CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 60,
        CURLOPT_HTTPHEADER => ['Content-Type: application/json', 'X-Auth-Token: ' . $tok], CURLOPT_POSTFIELDS => json_encode($body)]);
    curl_multi_add_handle($mh, $ch);
    $until = microtime(true) + 1.5;   // long enough to pass sign-in and reach the lock
    do { curl_multi_exec($mh, $running); usleep(20000); } while ($running && microtime(true) < $until);
    return [$mh, $ch];
}
function finishRequest(array $h): array
{
    [$mh, $ch] = $h;
    do { curl_multi_exec($mh, $running); if ($running) curl_multi_select($mh, 1.0); } while ($running);
    return [curl_getinfo($ch, CURLINFO_RESPONSE_CODE), json_decode((string) curl_multi_getcontent($ch), true)];
}
foreach (['/sync' => ['profile' => 'gone-profile', 'since' => '', 'records' => [rec('servers', $now)]],
          '/shares/create' => ['share_id' => bin2hex(random_bytes(16)), 'name' => 'Gone', 'sealed_dek' => 'ab']] as $gpath => $gbody) {
    $gone = mkuser('gone-' . bin2hex(random_bytes(3)) . '@stage.test');
    $pdo->beginTransaction();
    $pdo->prepare('SELECT id FROM users WHERE id = ? FOR UPDATE')->execute([$gone['id']]);
    $h = startRequest($gpath, $gbody, $gone['tok']);
    $pdo->prepare('DELETE FROM users WHERE id = ?')->execute([$gone['id']]);
    $pdo->commit();
    [$code, $json] = finishRequest($h);
    check("$gpath: 401 invalid_token", [$code, $json['error'] ?? null], [401, 'invalid_token']);
    check("$gpath: no counter, record or share row left", (int) one('SELECT
        (SELECT COUNT(*) FROM sync_revs WHERE user_id = ?) + (SELECT COUNT(*) FROM sync_records WHERE user_id = ?)
      + (SELECT COUNT(*) FROM shared_profiles WHERE owner_user_id = ?)', [$gone['id'], $gone['id'], $gone['id']]), 0);
}

section('a share deleted while a create waits for its row: 410, not made again');
$dw = mkuser('share-gone@stage.test');
$dwid = bin2hex(random_bytes(16));
api($dw, 'POST', '/shares/create', ['share_id' => $dwid, 'name' => 'D', 'sealed_dek' => 'ab']);
$pdo->beginTransaction();
$pdo->prepare('SELECT owner_user_id FROM shared_profiles WHERE share_id = ? FOR UPDATE')->execute([$dwid]);
$h = startRequest('/shares/create', ['share_id' => $dwid, 'name' => 'D2', 'sealed_dek' => 'ab'], $dw['tok']);
foreach (['profile_members', 'shared_profiles'] as $t) {
    $pdo->prepare("DELETE FROM `$t` WHERE share_id = ?")->execute([$dwid]);
}
$pdo->prepare('INSERT INTO deleted_shares (share_id, deleted_at) VALUES (?, ?)')->execute([$dwid, time()]);
$pdo->commit();
[$code, $json] = finishRequest($h);
check('410 share_deleted', [$code, $json['error'] ?? null], [410, 'share_deleted']);
check('the share stays deleted', (int) one('SELECT COUNT(*) FROM shared_profiles WHERE share_id = ?', [$dwid]), 0);

section('a share deleted while a push to it waits: 410, nothing of it left');
// The push passed its membership check and waits; the owner deletes the share;
// the push must not then write records (or a revision counter) for a share
// nobody can reach any more. Once while it makes the share's first counter (a
// gap lock holds its insert), once while it waits for an existing counter.
$sdel = function (string $sid): void {
    global $pdo;
    foreach (['shared_records', 'shared_revs', 'profile_members', 'shared_profiles'] as $t) {
        $pdo->prepare("DELETE FROM `$t` WHERE share_id = ?")->execute([$sid]);
    }
    $pdo->prepare('INSERT INTO deleted_shares (share_id, deleted_at) VALUES (?, ?)')->execute([$sid, time()]);
};
foreach (['first counter' => false, 'existing counter' => true] as $label => $hasCounter) {
    $pw = mkuser('push-gone-' . bin2hex(random_bytes(3)) . '@stage.test');
    $pwid = bin2hex(random_bytes(16));
    api($pw, 'POST', '/shares/create', ['share_id' => $pwid, 'name' => 'P', 'sealed_dek' => 'ab']);
    if ($hasCounter) {
        api($pw, 'POST', '/shares/sync', ['share_id' => $pwid, 'since' => '', 'records' => [rec('servers', $now)]]);
    }
    $pdo->beginTransaction();
    $pdo->prepare('SELECT rev FROM shared_revs WHERE share_id = ? FOR UPDATE')->execute([$pwid]);
    $h = startRequest('/shares/sync', ['share_id' => $pwid, 'since' => '', 'records' => [rec('servers', $now + 5)]], $pw['tok']);
    $sdel($pwid);
    $pdo->commit();
    [$code, $json] = finishRequest($h);
    check("$label: 410 share_deleted", [$code, $json['error'] ?? null], [410, 'share_deleted']);
    check("$label: no record or counter of the deleted share", (int) one('SELECT
        (SELECT COUNT(*) FROM shared_records WHERE share_id = ?) + (SELECT COUNT(*) FROM shared_revs WHERE share_id = ?)', [$pwid, $pwid]), 0);
}

section('a membership left behind for a deleted share opens nothing');
// A row that outlived its share (an invitation that crossed the deletion):
// the share is gone for every endpoint, and the clean-up removes the row.
$om = mkuser('orphan-member@stage.test');
$omid = bin2hex(random_bytes(16));
$pdo->prepare('INSERT INTO deleted_shares (share_id, deleted_at) VALUES (?, ?)')->execute([$omid, time()]);
$pdo->prepare('INSERT INTO profile_members (share_id, member_user_id, role, sealed_dek, status, invited_by, created_at)
               VALUES (?, ?, "editor", "ab", "pending", ?, ?)')->execute([$omid, $om['id'], $om['id'], time()]);
check('accept: 404', api($om, 'POST', '/shares/accept', ['share_id' => $omid])['code'], 404);
$pdo->prepare('UPDATE profile_members SET status = "active" WHERE share_id = ?')->execute([$omid]);
check('dek: 410', api($om, 'POST', '/shares/dek', ['share_id' => $omid])['code'], 410);
check('members: 403', api($om, 'POST', '/shares/members', ['share_id' => $omid])['code'], 403);
$r = api($om, 'POST', '/shares/sync', ['share_id' => $omid, 'since' => '', 'records' => [rec('servers', $now)]]);
check('sync: 410, nothing written', [$r['code'], (int) one('SELECT COUNT(*) FROM shared_records WHERE share_id = ?', [$omid])], [410, 0]);
$pdo->prepare('INSERT IGNORE INTO shared_records (share_id, uuid, entity_type, updated_at, deleted, rev) VALUES (?, "ab", "servers", ?, 1, 1)')
    ->execute([$omid, stamp($now)]);
$pdo->prepare('INSERT IGNORE INTO shared_revs (share_id, rev, epoch) VALUES (?, 1, "00000000000000ab")')->execute([$omid]);
exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(ROOT . '/bin/cron.php') . ' 2>&1', $cronOut, $cronRc);
check('cron removes what is left of a deleted share', [$cronRc, (int) one('SELECT
    (SELECT COUNT(*) FROM profile_members WHERE share_id = ?) + (SELECT COUNT(*) FROM shared_records WHERE share_id = ?)
  + (SELECT COUNT(*) FROM shared_revs WHERE share_id = ?)', [$omid, $omid, $omid])], [0, 0]);
check('cron keeps the deleted id itself', (int) one('SELECT COUNT(*) FROM deleted_shares WHERE share_id = ?', [$omid]), 1);

section('/shares/sync takes a record\'s blob only as text');
$sb = mkuser('share-blob@stage.test');
$sbid = bin2hex(random_bytes(16));
api($sb, 'POST', '/shares/create', ['share_id' => $sbid, 'name' => 'B', 'sealed_dek' => 'ab']);
$badRec = rec('servers', $now);
$badRec['blob'] = ['not', 'text'];
$goodRec = rec('servers', $now + 1);
$r = api($sb, 'POST', '/shares/sync', ['share_id' => $sbid, 'since' => '', 'records' => [$badRec, $goodRec]]);
check('the push answers, the bad record is dropped', [$r['code'],
    (int) one('SELECT COUNT(*) FROM shared_records WHERE share_id = ? AND uuid = ?', [$sbid, $badRec['uuid']]),
    (int) one('SELECT COUNT(*) FROM shared_records WHERE share_id = ? AND uuid = ?', [$sbid, $goodRec['uuid']])], [200, 0, 1]);

section('the profile cap counts the revision counters too');
setConfig(['quota' => ['profiles' => 10]]);
$u = mkuser('cap@stage.test');
$codes = [];
for ($i = 0; $i < 15; $i++) {
    $codes[] = api($u, 'POST', '/sync', ['profile' => bin2hex(random_bytes(16)), 'since' => '', 'records' => ['not an object']])['code'];
}
$held = (int) one('SELECT COUNT(*) FROM (SELECT profile FROM sync_records WHERE user_id = ? UNION SELECT profile FROM sync_revs WHERE user_id = ?) h', [$u['id'], $u['id']]);
check('never more than 10 profiles held, however they were made', $held <= 10, true);
check('the ones past the cap were refused (507)', in_array(507, $codes, true), true);
restoreConfig();

section('a counter row alone does not let a new profile past the cap');
// A push that stores nothing leaves a counter row; the cap is then lowered.
setConfig(['quota' => ['profiles' => 3]]);
$u = mkuser('cap-counter@stage.test');
foreach (['c1', 'c2'] as $p) api($u, 'POST', '/sync', ['profile' => $p, 'since' => '', 'records' => [rec('servers', $now)]]);
api($u, 'POST', '/sync', ['profile' => 'c3', 'since' => '', 'records' => ['not an object']]);
$revsOf = fn (string $p): int => (int) one('SELECT COUNT(*) FROM sync_revs WHERE user_id = ? AND profile = ?', [$u['id'], $p]);
check('the empty push left only a counter', [$revsOf('c3'), (int) one('SELECT COUNT(*) FROM sync_records WHERE user_id = ? AND profile = "c3"', [$u['id']])], [1, 0]);
setConfig(['quota' => ['profiles' => 2]]);
$r = api($u, 'POST', '/sync', ['profile' => 'c3', 'since' => '', 'records' => [rec('servers', $now)]]);
check('records for it are refused at the cap, and its counter goes', [$r['code'], $r['json']['error'] ?? null, $revsOf('c3'),
    (int) one('SELECT COUNT(DISTINCT profile) FROM sync_records WHERE user_id = ?', [$u['id']])], [507, 'quota_exceeded', 0, 2]);

section('a new profile refused for the quota keeps no counter (no slot is used up)');
setConfig(['quota' => ['profiles' => 3, 'records' => 3, 'bytes' => 4096]]);
$u = mkuser('quota-counter@stage.test');
$r = api($u, 'POST', '/sync', ['profile' => 'rows', 'since' => '', 'records' => array_map(fn () => rec('servers', $now), range(1, 4))]);
check('too many rows: 507, no counter', [$r['code'], $revsOf('rows')], [507, 0]);
$r = api($u, 'POST', '/sync', ['profile' => 'bytes', 'since' => '', 'records' => [rec('servers', $now, bin2hex(random_bytes(6000)))]]);
check('too many bytes: 507, no counter', [$r['code'], $revsOf('bytes')], [507, 0]);
$codes = [];
foreach (['n1', 'n2', 'n3'] as $p) $codes[] = api($u, 'POST', '/sync', ['profile' => $p, 'since' => '', 'records' => [rec('servers', $now)]])['code'];
check('all three profile slots are still free', $codes, [200, 200, 200]);
restoreConfig();

section('an object with thousands of keys is refused at once; big honest bodies are not');
$u = mkuser('flood@stage.test');
$flood = ['profile' => bin2hex(random_bytes(16)), 'since' => '', 'records' => []];
for ($i = 0; $i < 6000; $i++) $flood["k$i"] = 1;
$r = api($u, 'POST', '/sync', $flood);
check('6000 keys in one object: 400 bad_body, fast', [$r['code'], $r['json']['error'] ?? null, $r['ms'] < 3000], [400, 'bad_body', true]);
$records = [];
for ($i = 0; $i < 2000; $i++) $records[] = rec('servers', $now + $i);
$r = api($u, 'POST', '/sync', ['profile' => bin2hex(random_bytes(16)), 'since' => '', 'records' => $records]);
check('2000 records in a push: accepted', $r['code'], 200);
$r = req('POST', '/auth/login', str_repeat('[', 70) . str_repeat(']', 70) . str_repeat(' ', 17000), [], 'application/json');
check('a body nested too deep is refused', [$r['code'], $r['json']['error'] ?? null], [400, 'bad_body']);

// ===========================================================================
section('deleting an account from the app: token and password');
$r = req('POST', '/auth/delete-account', ['password' => 'x']);
check('no token: 401', $r['code'], 401);
$u = mkuser('del1@stage.test', 'right password 1');
$r = api($u, 'POST', '/auth/delete-account', []);
check('no password: 403 reauth_required', [$r['code'], $r['json']['error'] ?? null], [403, 'reauth_required']);
check('and it does not count as a failed login', (int) one('SELECT failed_login_count FROM users WHERE id = ?', [$u['id']]), 0);
$r = api($u, 'POST', '/auth/delete-account', ['password' => 'wrong password']);
check('a wrong password: 403, counted', [$r['code'], (int) one('SELECT failed_login_count FROM users WHERE id = ?', [$u['id']])], [403, 1]);
// bcrypt stops reading at a NUL: the right password with anything after one
// must not pass for it.
$r = api($u, 'POST', '/auth/delete-account', ['password' => "right password 1\0anything"]);
check('the right password, a NUL and more: 403, counted, still there', [$r['code'],
    (int) one('SELECT failed_login_count FROM users WHERE id = ?', [$u['id']]), (int) one('SELECT COUNT(*) FROM users WHERE id = ?', [$u['id']])], [403, 2, 1]);

section('the right password removes everything of the user');
$own = bin2hex(random_bytes(16));
$theirs = bin2hex(random_bytes(16));
$v = mkuser('del-owner@stage.test', 'owner password 1');
$m = mkuser('del-member@stage.test', 'member password 1');
api($u, 'POST', '/sync', ['profile' => 'p1', 'since' => '', 'records' => [rec('servers', $now), rec('servers', $now + 1)], 'name' => 'Mine']);
api($u, 'POST', '/keys/publish', ['public_key' => bin2hex(random_bytes(32)), 'wrapped_privkey' => 'ab', 'enc_salt' => 'cd']);
api($u, 'POST', '/shares/create', ['share_id' => $own, 'name' => 'MyShare', 'sealed_dek' => 'ab']);
api($u, 'POST', '/shares/invite', ['share_id' => $own, 'email' => 'del-member@stage.test', 'role' => 'editor', 'sealed_dek' => 'ab']);
api($u, 'POST', '/shares/sync', ['share_id' => $own, 'since' => '', 'records' => [rec('servers', $now)]]);
api($v, 'POST', '/shares/create', ['share_id' => $theirs, 'name' => 'TheirShare', 'sealed_dek' => 'ab']);
api($v, 'POST', '/shares/invite', ['share_id' => $theirs, 'email' => 'del1@stage.test', 'role' => 'editor', 'sealed_dek' => 'ab']);
api($v, 'POST', '/shares/sync', ['share_id' => $theirs, 'since' => '', 'records' => [rec('servers', $now), rec('servers', $now + 1)]]);
$pdo->prepare('UPDATE shared_records SET last_writer = ? WHERE share_id = ? LIMIT 1')->execute([$u['id'], $theirs]);
clearRL();
$r = api($u, 'POST', '/auth/delete-account', ['password' => 'right password 1']);
check('the right password: 200 ok', [$r['code'], $r['json']['ok'] ?? null], [200, true]);
$left = [];
foreach (['sync_records', 'sync_revs', 'sync_profiles', 'user_keys', 'auth_tokens', 'auth_events'] as $t) {
    $left[$t] = (int) one("SELECT COUNT(*) FROM `$t` WHERE user_id = ?", [$u['id']]);
}
$left['memberships'] = (int) one('SELECT COUNT(*) FROM profile_members WHERE member_user_id = ?', [$u['id']]);
$left['owned share'] = (int) one('SELECT COUNT(*) FROM shared_profiles WHERE share_id = ?', [$own]);
$left['its records'] = (int) one('SELECT COUNT(*) FROM shared_records WHERE share_id = ?', [$own]);
$left['its counter'] = (int) one('SELECT COUNT(*) FROM shared_revs WHERE share_id = ?', [$own]);
$left['its members'] = (int) one('SELECT COUNT(*) FROM profile_members WHERE share_id = ?', [$own]);
$left['codes'] = (int) one('SELECT COUNT(*) FROM verify_tokens WHERE user_id = ?', [$u['id']]);
$left['user'] = (int) one('SELECT COUNT(*) FROM users WHERE id = ?', [$u['id']]);
check('nothing of the user is left', [array_sum($left), $left], [0, $left]);
check('the id of the deleted share can not be taken again', (int) one('SELECT COUNT(*) FROM deleted_shares WHERE share_id = ?', [$own]), 1);
check('the other owner\'s share is still there, with its records', [
    (int) one('SELECT COUNT(*) FROM shared_profiles WHERE share_id = ?', [$theirs]),
    (int) one('SELECT COUNT(*) FROM shared_records WHERE share_id = ?', [$theirs]),
], [1, 2]);
check('what the user wrote there stays, with no writer named', (int) one('SELECT COUNT(*) FROM shared_records WHERE last_writer = ?', [$u['id']]), 0);
check('the token is dead: 401', api($u, 'GET', '/sync/profiles')['code'], 401);
check('the deletion is in the log, with no email and no user', (int) one(
    "SELECT COUNT(*) FROM auth_events WHERE event = 'account_deleted' AND email IS NULL AND user_id IS NULL AND detail LIKE ?", ['uid=' . $u['id'] . '%']), 1);
check('other accounts are untouched', (int) one('SELECT COUNT(*) FROM users WHERE id IN (?, ?)', [$v['id'], $m['id']]), 2);

section('deleting: limits and the lock');
$w = mkuser('del2@stage.test', 'right password 2');
$codes = [];
for ($i = 0; $i < 5; $i++) $codes[] = api($w, 'POST', '/auth/delete-account', ['password' => 'wrong ' . $i])['code'];
check('five wrong passwords: 403 each', $codes, [403, 403, 403, 403, 403]);
check('they locked the account', one('SELECT locked_until FROM users WHERE id = ?', [$w['id']]) !== null, true);
check('the sixth try in the hour: 429', api($w, 'POST', '/auth/delete-account', ['password' => 'right password 2'])['code'], 429);
clearRL();
check('a locked account is refused with the right password', api($w, 'POST', '/auth/delete-account', ['password' => 'right password 2'])['code'], 403);
$pdo->prepare('UPDATE users SET locked_until = NULL, failed_login_count = 0 WHERE id = ?')->execute([$w['id']]);
clearRL();
$r = api($w, 'POST', '/auth/delete-account', ['password' => 'right password 2']);
check('unlocked: the right password deletes it', [$r['code'], (int) one('SELECT COUNT(*) FROM users WHERE id = ?', [$w['id']])], [200, 0]);

section('a suspended account');
$s = mkuser('suspend@stage.test', 'right password 3');
$madeBefore = mktoken($s['id'], 'login');
[$rc] = cli('suspend', 'suspend@stage.test');
check('cli suspend', $rc, 0);
check('its token is gone', api($s, 'GET', '/sync/profiles')['code'], 401);
clearRL();
check('it can not sign in', req('POST', '/auth/login', ['email' => 'suspend@stage.test', 'password' => 'right password 3'])['code'], 401);
$code = mktoken($s['id'], 'login');
check('nor with a sign-in code', req('POST', '/auth/login-with-link', ['login_token' => $code])['code'], 403);
[$rc] = cli('unsuspend', 'suspend@stage.test');
clearRL();
check('unsuspended: it signs in again', [$rc, req('POST', '/auth/login', ['email' => 'suspend@stage.test', 'password' => 'right password 3'])['code']], [0, 200]);
check('a sign-in code made before the suspension is gone', req('POST', '/auth/login-with-link', ['login_token' => $madeBefore])['code'], 400);

section('a new password or a sign-out everywhere ends the account\'s codes');
$cu = mkuser('codes@stage.test', 'codes password 1');
$login1 = mktoken($cu['id'], 'login');
$reset1 = mktoken($cu['id'], 'reset');
check('a new password with a reset code', req('POST', '/auth/reset-with-token', ['reset_token' => $reset1, 'password' => 'codes password 2'])['code'], 200);
check('a sign-in code from before the new password no longer works', req('POST', '/auth/login-with-link', ['login_token' => $login1])['code'], 400);
$login2 = mktoken($cu['id'], 'login');
[, $out] = cli('reset-code', 'codes@stage.test');
preg_match('/^\s{4}([0-9a-f]{48})$/m', $out, $m);
[$rc] = cli('signout', 'codes@stage.test');
check('sign out everywhere: the sign-in code and the admin\'s reset code no longer work', [$rc,
    req('POST', '/auth/login-with-link', ['login_token' => $login2])['code'],
    req('POST', '/auth/reset-with-token', ['reset_token' => $m[1] ?? '', 'password' => 'codes password 3'])['code']], [0, 400, 400]);

section('failures of no account: at most 60 log rows an hour per address');
$before = (int) one("SELECT COUNT(*) FROM auth_events WHERE event = 'invalid_token'");
for ($i = 0; $i < 70; $i++) req('GET', '/sync/profiles', null, ['X-Auth-Token' => str_repeat('ab', 32)]);
check('70 unknown tokens: 60 rows', (int) one("SELECT COUNT(*) FROM auth_events WHERE event = 'invalid_token'") - $before, 60);
check('the rate limits still count every one', (int) one("SELECT SUM(hits) FROM rate_limits WHERE bucket = 'global:ip:127.0.0.1'") >= 70, true);
$ku = mkuser('still-logged@stage.test');
clearRL();
for ($i = 0; $i < 3; $i++) req('POST', '/auth/login', ['email' => 'nobody-here@stage.test', 'password' => 'x pw 123']);
api($ku, 'GET', '/sync/profiles');
check('a known account\'s events are always logged', (int) one("SELECT COUNT(*) FROM auth_events WHERE user_id = ? AND event = 'sync_profiles'", [$ku['id']]), 1);

done();
