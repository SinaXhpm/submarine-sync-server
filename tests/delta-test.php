<?php
// Delta sync: per-partition revisions, answers
// with only what changed since the client's revision, no echo of its own
// writes, the server's copy of what it sent stale, full answers (`full: true`)
// to a stale epoch or revision, and released apps (no since_rev) unchanged.
//   php tests/delta-test.php
declare(strict_types=1);
require __DIR__ . '/lib.php';

wipe();
$now = (int) (microtime(true) * 1000);
$u = mkuser('dl-' . bin2hex(random_bytes(4)) . '@example.com');
$P = bin2hex(random_bytes(16));
$sync = fn(array $body) => api($u, 'POST', '/sync', $body + ['profile' => $P, 'since' => '']);
$uuids = fn(array $r) => array_map(fn($x) => $x['uuid'], $r['json']['records'] ?? []);
$sorted = function (array $a) { sort($a); return $a; };
$mk = fn(string $uuid, int $ms, bool $deleted = false) => ['uuid' => $uuid, 'entity_type' => 'servers', 'updated_at' => stamp($ms), 'deleted' => $deleted] + ($deleted ? [] : ['blob' => bin2hex(random_bytes(30))]);
$a = bin2hex(random_bytes(16)); $b = bin2hex(random_bytes(16)); $x = bin2hex(random_bytes(16)); $y = bin2hex(random_bytes(16));

section('released apps (no since_rev): full answers as before');
$r = $sync(['records' => [$mk($a, $now + 1), $mk($b, $now + 2)]]);
check('push answered in full, echo included', [$r['code'], $sorted($uuids($r))], [200, $sorted([$a, $b])]);
check('the answer carries a cursor (released apps ignore it)', [is_int($r['json']['rev'] ?? null), strlen((string) ($r['json']['epoch'] ?? ''))], [true, 16]);
check('no full flag without since_rev', array_key_exists('full', $r['json']), false);
$rev = $r['json']['rev'];
$epoch = $r['json']['epoch'];
check('two writes, revision 2', $rev, 2);

section('delta: nothing new');
$r = $sync(['records' => [], 'since_rev' => $rev, 'epoch' => $epoch]);
check('empty answer, same revision', [$r['code'], $uuids($r), $r['json']['rev'] ?? null, $r['json']['full'] ?? null], [200, [], 2, null]);

section("another device's write comes as a delta");
$r = $sync(['records' => [$mk($x, $now + 3)]]); // an old-style client
$r = $sync(['records' => [], 'since_rev' => $rev, 'epoch' => $epoch]);
check('only x', [$uuids($r), $r['json']['rev']], [[$x], 3]);
$rev = $r['json']['rev'];

section('own writes are not echoed');
$r = $sync(['records' => [$mk($y, $now + 4)], 'since_rev' => $rev, 'epoch' => $epoch]);
check('y stored, not sent back', [$uuids($r), $r['json']['rev'], (int) one('SELECT COUNT(*) FROM sync_records WHERE user_id = ? AND profile = ? AND uuid = ?', [$u['id'], $P, $y])], [[], 4, 1]);
$rev = $r['json']['rev'];

section('a stale push gets the server copy back');
$r = $sync(['records' => [$mk($x, $now + 1)], 'since_rev' => $rev, 'epoch' => $epoch]);
check('older x refused, the newer one sent', [$uuids($r), $r['json']['records'][0]['updated_at'] ?? null, $r['json']['rev']], [[$x], stamp($now + 3), 4]);
$r = $sync(['records' => [$mk($x, $now + 3)], 'since_rev' => $rev, 'epoch' => $epoch]);
check('the same stamp: nothing back', $uuids($r), []);

section('deletions');
$r = $sync(['records' => [$mk($a, $now + 5, true)]]);
$r = $sync(['records' => [], 'since_rev' => $rev, 'epoch' => $epoch]);
check('the tombstone comes as a delta', [$uuids($r), $r['json']['records'][0]['deleted'] ?? null], [[$a], true]);
$rev = $r['json']['rev'];

section('a cursor the server can\'t serve: full answer');
$r = $sync(['records' => [], 'since_rev' => $rev, 'epoch' => '0123456789abcdef']);
check('wrong epoch: everything, full', [count($uuids($r)), $r['json']['full'] ?? null, $r['json']['epoch']], [4, true, $epoch]);
$r = $sync(['records' => [], 'since_rev' => $rev + 100, 'epoch' => $epoch]);
check('a revision past the counter: everything, full', [count($uuids($r)), $r['json']['full'] ?? null], [4, true]);
$r = $sync(['records' => [], 'since_rev' => -1, 'epoch' => $epoch]);
check('a bad since_rev reads as none (full answer, no flag)', [count($uuids($r)), $r['json']['full'] ?? null], [4, null]);

section('deleting the profile starts a new epoch');
$r = api($u, 'POST', '/sync/delete', ['profile' => $P]);
check('deleted', [$r['code'], (int) one('SELECT COUNT(*) FROM sync_revs WHERE user_id = ? AND profile = ?', [$u['id'], $P])], [200, 0]);
$z = bin2hex(random_bytes(16));
$r = $sync(['records' => [$mk($z, $now + 6)], 'since_rev' => $rev, 'epoch' => $epoch]);
check('the old cursor gets a full answer under a new epoch', [$uuids($r), $r['json']['full'] ?? null, $r['json']['epoch'] !== $epoch, $r['json']['rev']], [[$z], true, true, 1]);

section('a profile from before delta sync (rows at revision 0, no counter)');
$old = bin2hex(random_bytes(16));
$o1 = bin2hex(random_bytes(16));
$pdo->prepare('INSERT INTO sync_records (user_id, profile, uuid, entity_type, updated_at, deleted, `blob`) VALUES (?, ?, ?, ?, ?, 0, ?)')
    ->execute([$u['id'], $old, $o1, 'servers', stamp($now), 'ab']);
$r = api($u, 'POST', '/sync', ['profile' => $old, 'since' => '', 'records' => []]);
check('a pull: everything, and a counter now', [$uuids($r), $r['json']['rev'] ?? null, strlen((string) ($r['json']['epoch'] ?? ''))], [[$o1], 0, 16]);
$e0 = $r['json']['epoch'];
$r = api($u, 'POST', '/sync', ['profile' => $old, 'since' => '', 'records' => [], 'since_rev' => 0, 'epoch' => $e0]);
check('delta from 0: nothing (the old row came in full)', [$uuids($r), $r['json']['full'] ?? null], [[], null]);
$o2 = bin2hex(random_bytes(16));
$r = api($u, 'POST', '/sync', ['profile' => $old, 'since' => '', 'records' => [$mk($o2, $now + 1)]]);
$r = api($u, 'POST', '/sync', ['profile' => $old, 'since' => '', 'records' => [], 'since_rev' => 0, 'epoch' => $e0]);
check('a later write comes', $uuids($r), [$o2]);

section('a counter made again starts above the rows it finds');
// The counter row lost while the rows keep their revisions (a restore, say).
$pdo->prepare('DELETE FROM sync_revs WHERE user_id = ? AND profile = ?')->execute([$u['id'], $old]);
$r = api($u, 'POST', '/sync', ['profile' => $old, 'since' => '', 'records' => []]);
$e1 = $r['json']['epoch'];
check('a new epoch, the counter at the highest revision held', [$e1 !== $e0, $r['json']['rev']], [true, 1]);
$r = api($u, 'POST', '/sync', ['profile' => $old, 'since' => '', 'records' => [], 'since_rev' => $r['json']['rev'], 'epoch' => $e1]);
check('so a delta from it brings no old row', $uuids($r), []);

section('a pull of a profile that does not exist makes nothing');
$ghost = bin2hex(random_bytes(16));
$r = api($u, 'POST', '/sync', ['profile' => $ghost, 'since' => '', 'records' => []]);
check('empty, no cursor, no counter row', [$uuids($r), array_key_exists('rev', $r['json']), (int) one('SELECT COUNT(*) FROM sync_revs WHERE profile = ?', [$ghost])], [[], false, 0]);

section('parallel writers: every write gets its own revision');
$Q = bin2hex(random_bytes(16));
$r = api($u, 'POST', '/sync', ['profile' => $Q, 'since' => '', 'records' => [$mk(bin2hex(random_bytes(16)), $now)]]);
$qe = $r['json']['epoch']; $qr = $r['json']['rev'];
$mh = curl_multi_init(); $hs = [];
$sent = [];
for ($i = 0; $i < 12; $i++) {
    $id = bin2hex(random_bytes(16)); $sent[] = $id;
    $ch = curl_init(BASE . '/sync');
    curl_setopt_array($ch, [CURLOPT_POST => true, CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 60,
        CURLOPT_HTTPHEADER => ['Content-Type: application/json', 'X-Auth-Token: ' . $u['tok']],
        CURLOPT_POSTFIELDS => json_encode(['profile' => $Q, 'since' => '', 'records' => [$mk($id, $now + 10 + $i)]])]);
    curl_multi_add_handle($mh, $ch); $hs[] = $ch;
}
do { $st = curl_multi_exec($mh, $running); if ($running) curl_multi_select($mh, 1.0); } while ($running && $st === CURLM_OK);
$codes = array_map(fn($ch) => curl_getinfo($ch, CURLINFO_RESPONSE_CODE), $hs);
check('all 12 went through', array_count_values($codes), [200 => 12]);
$revs = array_map(fn($row) => (int) $row['rev'], rows('SELECT rev FROM sync_records WHERE user_id = ? AND profile = ?', [$u['id'], $Q]));
sort($revs);
check('13 rows, revisions 1..13, each once', $revs, range(1, 13));
$r = api($u, 'POST', '/sync', ['profile' => $Q, 'since' => '', 'records' => [], 'since_rev' => $qr, 'epoch' => $qe]);
check('a delta from before them has all 12', [$sorted($uuids($r)), $r['json']['rev']], [$sorted($sent), 13]);

section('shared profiles');
$bob = mkuser('dlb-' . bin2hex(random_bytes(4)) . '@example.com');
$sid = bin2hex(random_bytes(16));
check('share made', api($u, 'POST', '/shares/create', ['share_id' => $sid, 'name' => 'Team', 'sealed_dek' => bin2hex(random_bytes(48))])['code'], 200);
$s1 = bin2hex(random_bytes(16)); $s2 = bin2hex(random_bytes(16));
$r = api($u, 'POST', '/shares/sync', ['share_id' => $sid, 'since' => '', 'records' => [$mk($s1, $now)]]);
check('full push, cursor', [$uuids($r), $r['json']['rev'] ?? null], [[$s1], 1]);
$se = $r['json']['epoch'];
$r = api($u, 'POST', '/shares/sync', ['share_id' => $sid, 'since' => '', 'records' => [$mk($s2, $now + 1)], 'since_rev' => 1, 'epoch' => $se]);
check('own write not echoed', [$uuids($r), $r['json']['rev']], [[], 2]);
$r = api($u, 'POST', '/shares/sync', ['share_id' => $sid, 'since' => '', 'records' => [], 'since_rev' => 1, 'epoch' => $se]);
check('a delta from 1 has s2', $uuids($r), [$s2]);
$r = api($u, 'POST', '/shares/sync', ['share_id' => $sid, 'since' => '', 'records' => [], 'since_rev' => 1, 'epoch' => 'ffffffffffffffff']);
check('wrong epoch: full', [count($uuids($r)), $r['json']['full'] ?? null], [2, true]);
check('share deleted, counter gone', [api($u, 'POST', '/shares/delete', ['share_id' => $sid])['code'], (int) one('SELECT COUNT(*) FROM shared_revs WHERE share_id = ?', [$sid])], [200, 0]);

done();
