<?php
// Sync compression: POST /sync and POST
// /shares/sync take a gzipped body, advertise it (Accept-Encoding: gzip on the
// answer), and gzip a big answer for a client that asks; everything else
// stays plain and refuses a compressed body. Plus the limits: a gzip bomb, a
// body that inflates past the cap, garbage, an unknown encoding.
//   php tests/gzip-test.php
declare(strict_types=1);
require __DIR__ . '/lib.php';

wipe();
$now = (int) (microtime(true) * 1000);
$u = mkuser('gz-' . bin2hex(random_bytes(4)) . '@example.com');
$profile = bin2hex(random_bytes(16));
$hdr = fn(array $r, string $name): ?string => preg_match('/^' . preg_quote($name, '/') . ':\s*(.+?)\r?$/mi', $r['headers'], $m) ? $m[1] : null;
$records = fn(int $n, int $base) => array_map(fn($i) => rec('servers', $base + $i, bin2hex(random_bytes(200))), range(1, $n));
$gz = fn(array $body) => gzencode(json_encode($body), 6);

section('plain, as released apps do');
$r = api($u, 'POST', '/sync', ['profile' => $profile, 'since' => '', 'records' => $records(5, $now)]);
check('plain /sync works', $r['code'], 200);
check('answer not compressed', $hdr($r, 'Content-Encoding'), null);
check('answer says gzipped bodies are taken', $hdr($r, 'Accept-Encoding'), 'gzip');
check('5 records back', count($r['json']['records'] ?? []), 5);

section('a big answer, gzipped when asked');
$r = req('POST', '/sync', ['profile' => $profile, 'since' => '', 'records' => []], ['X-Auth-Token' => $u['tok'], 'Accept-Encoding' => 'gzip']);
check('200', $r['code'], 200);
check('Content-Encoding: gzip', $hdr($r, 'Content-Encoding'), 'gzip');
check('Vary: Accept-Encoding', $hdr($r, 'Vary'), 'Accept-Encoding');
$plain = @gzdecode($r['body']);
check('decodes to the same 5 records', count(json_decode((string) $plain, true)['records'] ?? []), 5);
check('and is smaller', strlen($r['body']) < strlen((string) $plain), true);
$r = req('POST', '/sync', ['profile' => $profile, 'since' => '', 'records' => []], ['X-Auth-Token' => $u['tok'], 'Accept-Encoding' => 'gzip;q=0, identity']);
check('gzip;q=0: plain', [$r['code'], $hdr($r, 'Content-Encoding')], [200, null]);

section('a gzipped body');
$body = $gz(['profile' => $profile, 'since' => '', 'records' => $records(20, $now + 100)]);
$r = req('POST', '/sync', $body, ['X-Auth-Token' => $u['tok'], 'Content-Encoding' => 'gzip'], 'application/json');
check('taken', $r['code'], 200);
check('stored: 25 records in the profile', (int) one('SELECT COUNT(*) FROM sync_records WHERE user_id = ? AND profile = ?', [$u['id'], $profile]), 25);

section('limits');
$t = microtime(true);
$bomb = shell_exec('head -c 200M /dev/zero | gzip -9');
$r = req('POST', '/sync', $bomb, ['X-Auth-Token' => $u['tok'], 'Content-Encoding' => 'gzip'], 'application/json');
check('a gzip bomb (200 MiB of zeros) is refused', [$r['code'], $r['json']['error'] ?? null], [400, 'bad_body']);
check('quickly (< 2 s)', $r['ms'] < 2000, true);
$big = $gz(['profile' => $profile, 'since' => '', 'records' => [], 'pad' => str_repeat('x', 4 * 1024 * 1024)]);
$r = req('POST', '/sync', $big, ['X-Auth-Token' => $u['tok'], 'Content-Encoding' => 'gzip'], 'application/json');
check('inflating past 4 MiB is refused', $r['code'], 413);
$r = req('POST', '/sync', 'not gzip at all', ['X-Auth-Token' => $u['tok'], 'Content-Encoding' => 'gzip'], 'application/json');
check('garbage marked gzip is refused', [$r['code'], $r['json']['error'] ?? null], [400, 'bad_body']);
$r = req('POST', '/sync', json_encode(['profile' => $profile, 'since' => '', 'records' => []]), ['X-Auth-Token' => $u['tok'], 'Content-Encoding' => 'br'], 'application/json');
check('another encoding is refused', [$r['code'], $r['json']['error'] ?? null], [415, 'unsupported_content_encoding']);
$r = req('POST', '/sync', $gz(['profile' => $profile, 'since' => '', 'records' => []]), ['Content-Encoding' => 'gzip'], 'application/json');
check('without a token: refused before the body is read', $r['code'], 401);

section('everything else stays plain');
$r = req('POST', '/auth/login', $gz(['email' => $u['email'], 'password' => $u['pw']]), ['Content-Encoding' => 'gzip'], 'application/json');
check('a gzipped login is refused', [$r['code'], $r['json']['error'] ?? null], [415, 'unsupported_content_encoding']);
$r = req('POST', '/auth/login', ['email' => $u['email'], 'password' => $u['pw']], ['Accept-Encoding' => 'gzip']);
check('the login answer (a token) is never compressed', [$r['code'], $hdr($r, 'Content-Encoding'), $hdr($r, 'Accept-Encoding')], [200, null, null]);
$r = req('GET', '/sync/profiles', null, ['X-Auth-Token' => $u['tok'], 'Accept-Encoding' => 'gzip']);
check('/sync/profiles: plain, nothing advertised', [$r['code'], $hdr($r, 'Content-Encoding'), $hdr($r, 'Accept-Encoding')], [200, null, null]);

section('shared profiles');
$bob = mkuser('gzb-' . bin2hex(random_bytes(4)) . '@example.com');
$sid = bin2hex(random_bytes(16));
$r = api($u, 'POST', '/shares/create', ['share_id' => $sid, 'name' => 'Team', 'sealed_dek' => bin2hex(random_bytes(48))]);
check('share made', $r['code'], 200);
$r = req('POST', '/shares/sync', $gz(['share_id' => $sid, 'since' => '', 'records' => $records(8, $now + 300)]), ['X-Auth-Token' => $u['tok'], 'Content-Encoding' => 'gzip', 'Accept-Encoding' => 'gzip'], 'application/json');
check('gzipped /shares/sync taken', $r['code'], 200);
check('answer gzipped, 8 records', [$hdr($r, 'Content-Encoding'), count(json_decode((string) @gzdecode($r['body']), true)['records'] ?? [])], ['gzip', 8]);
check('advertised there too', $hdr($r, 'Accept-Encoding'), 'gzip');
$r = api($u, 'POST', '/shares/sync', ['share_id' => $sid, 'since' => '', 'records' => []]);
check('plain /shares/sync still works', [$r['code'], count($r['json']['records'] ?? [])], [200, 8]);

done();
