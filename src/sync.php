<?php
// POST /sync  [auth] — one profile's records, both ways.
//
// Body : { "profile": "<partition>", "name": "<label>", "since": "<stamp>",
//          "since_rev": <int>, "epoch": "<hex>",
//          "records": [ {uuid, entity_type, updated_at, deleted, blob?}, ... ] }
// Reply: { "records": [ ... ], "rev": <int>, "epoch": "<hex>", "full"?: true }
//
// The incoming records are merged in (last write wins on `updated_at`), then
// the client gets what changed: since its revision when it sent one (delta
// sync, src/lib/SyncDelta.php), otherwise everything newer than `since`.
//
// `blob` is an encrypted record as hex. The server never decrypts it; it only
// orders records by their plain `updated_at` stamps.
//
// Runs inside src/api.php's try{} with $db, $auth, $rl, $audit, $config, $ip.

use Submarine\Lib\SyncDelta;
use Submarine\Lib\Util;

if (!defined('SUBMARINE_API')) {
    http_response_code(404);
    exit;
}

$c = $auth->requireAuth($ip);
[$uMax, $uWindow] = $config['limits']['rate_user_global'];
$rl->enforce("user:{$c['user_id']}:global", $uMax, $uWindow);

// Record sets go gzipped both ways when the client does that (see Util).
Util::enableCompression();
$body    = Util::readJson(4 * 1024 * 1024);
$profile = trim(Util::str($body, 'profile'));
$since   = Util::str($body, 'since');
$records = $body['records'] ?? [];
// The profile's label for the picker on other devices. A malformed one is
// dropped rather than failing the sync over it.
$name    = trim(Util::str($body, 'name'));
if ($name !== '' && !preg_match('/^[A-Za-z0-9_\-]{1,32}\z/', $name)) {
    $name = '';
}
if ($profile === '' || !preg_match('/^[A-Za-z0-9_\-]{1,32}\z/', $profile)) {
    Util::sendError(400, 'invalid_input', 'profile (1-32 chars) required');
}
if (!is_array($records)) {
    Util::sendError(400, 'invalid_input', 'records must be an array');
}
if (count($records) > 5000) {
    Util::sendError(413, 'too_many_records', 'max 5000 records per sync');
}

// Per-account storage: the bytes of all its profiles' records (stored as hex,
// so LENGTH/2), the number of rows (a deletion has no blob and costs no bytes)
// and the number of profiles. Checked after the push and before the commit, so
// a push over a limit stores nothing. A push that doesn't grow the account is
// always taken, so a full account can delete its way back under.
$QUOTA_BYTES  = (int) $config['quota']['bytes'];
$MAX_ROWS     = (int) $config['quota']['records'];
$MAX_PROFILES = (int) $config['quota']['profiles'];
$quotaText    = round($QUOTA_BYTES / (1024 * 1024), 1) . ' MB';
$usedQ = $db->prepare('SELECT COUNT(*) AS n, COALESCE(SUM(LENGTH(`blob`)), 0) AS hex FROM sync_records WHERE user_id = ?');

// How many profiles the account holds besides this one. Held means: it has
// records, or (with $counters) a revision counter, which any push with
// records makes, stored or not.
$heldOthers = static function (bool $counters) use ($db, $c, $profile): int {
    if (!$counters) {
        $q = $db->prepare('SELECT COUNT(DISTINCT profile) FROM sync_records WHERE user_id = ? AND profile <> ?');
        $q->execute([$c['user_id'], $profile]);
        return (int) $q->fetchColumn();
    }
    $q = $db->prepare(
        'SELECT COUNT(*) FROM (
            SELECT profile FROM sync_records WHERE user_id = ? AND profile <> ?
            UNION SELECT profile FROM sync_revs WHERE user_id = ? AND profile <> ?
         ) held'
    );
    $q->execute([$c['user_id'], $profile, $c['user_id'], $profile]);
    return (int) $q->fetchColumn();
};
$isNew = false;
if ($records) {
    // A profile the server doesn't hold yet must fit under the profile cap.
    $known = $db->prepare(
        'SELECT 1 FROM sync_records WHERE user_id = ? AND profile = ?
         UNION ALL SELECT 1 FROM sync_revs WHERE user_id = ? AND profile = ? LIMIT 1'
    );
    $known->execute([$c['user_id'], $profile, $c['user_id'], $profile]);
    $isNew = $known->fetchColumn() === false;
    if ($isNew && $heldOthers(true) >= $MAX_PROFILES) {
        $audit->log($c['user_id'], $c['email'], $ip, 'sync', false, "profile=$profile too_many_profiles");
        Util::sendError(507, 'quota_exceeded',
            "Cloud profile limit reached ($MAX_PROFILES per account). Delete a profile from the cloud, then sync again.");
    }
}

// Delta sync: the profile's revision counter, made before the transaction and
// locked inside it for the whole exchange (src/lib/SyncDelta.php).
$partition = ['user_id' => $c['user_id'], 'profile' => $profile];
SyncDelta::ensure($db, 'sync_revs', 'sync_records', $partition, (bool) $records);
// After a rollback: the counter row made above goes again while the profile
// has no records, so it doesn't hold a profile slot that no list shows.
$dropEmptyCounter = static function () use ($db, $c, $profile): void {
    $db->prepare('DELETE FROM sync_revs WHERE user_id = ? AND profile = ?
                   AND NOT EXISTS (SELECT 1 FROM sync_records WHERE user_id = ? AND profile = ?)')
       ->execute([$c['user_id'], $profile, $c['user_id'], $profile]);
};

$db->beginTransaction();
// The account's row first: one exchange per account at a time, so two pushes
// to different profiles can't both read the usage before either has written
// and pass the caps together. (Every path that takes more locks takes this
// one first; src/lib/Account.php does the same.)
$lockMe = $db->prepare('SELECT id FROM users WHERE id = ? FOR UPDATE');
$lockMe->execute([$c['user_id']]);
if ($lockMe->fetchColumn() === false) {
    // The account was deleted while this request waited: nothing of this
    // exchange stays, the counter row made above included.
    $db->rollBack();
    $dropEmptyCounter();
    Util::sendError(401, 'invalid_token', 'Unknown token');
}
// Under the lock, the cap again, for any profile that holds no records yet:
// "new" is decided again here, because a counter row alone (made by a push
// that stored nothing) made it look known above. The others are counted by
// their records only: pushes running at the same moment have made their
// counter rows already, before their own transaction.
if ($records) {
    $hasRows = $db->prepare('SELECT 1 FROM sync_records WHERE user_id = ? AND profile = ? LIMIT 1');
    $hasRows->execute([$c['user_id'], $profile]);
    $isNew = $hasRows->fetchColumn() === false;
}
if ($isNew && $heldOthers(false) >= $MAX_PROFILES) {
    // Another push made a profile while this one waited. This one's counter
    // row, made above, goes again so it doesn't count as held.
    $db->rollBack();
    $dropEmptyCounter();
    $audit->log($c['user_id'], $c['email'], $ip, 'sync', false, "profile=$profile too_many_profiles");
    Util::sendError(507, 'quota_exceeded',
        "Cloud profile limit reached ($MAX_PROFILES per account). Delete a profile from the cloud, then sync again.");
}
$delta = SyncDelta::open($db, 'sync_revs', 'sync_records', $partition, $body);

$usedQ->execute([$c['user_id']]);
$usedBefore = $usedQ->fetch();

// Last write wins on updated_at. updated_at is set LAST so every IF() compares
// with the old value. A row that changes takes this write's revision.
$up = $db->prepare(
    "INSERT INTO sync_records (user_id, profile, uuid, entity_type, updated_at, deleted, `blob`, rev)
     VALUES (:uid, :profile, :uuid, :etype, :uat, :deleted, :blob, :rev)
     ON DUPLICATE KEY UPDATE
        entity_type = IF(VALUES(updated_at) > updated_at, VALUES(entity_type), entity_type),
        deleted     = IF(VALUES(updated_at) > updated_at, VALUES(deleted), deleted),
        `blob`      = IF(VALUES(updated_at) > updated_at, VALUES(`blob`), `blob`),
        rev         = IF(VALUES(updated_at) > updated_at, VALUES(rev), rev),
        updated_at  = IF(VALUES(updated_at) > updated_at, VALUES(updated_at), updated_at)"
);

$accepted = 0;
foreach ($records as $r) {
    if (!is_array($r)) {
        continue;
    }
    $uuid  = Util::str($r, 'uuid');
    $etype = Util::str($r, 'entity_type');
    $uat   = Util::str($r, 'updated_at');
    // \z, not $: a $ also matches before a trailing newline.
    if (!preg_match('/^[0-9a-f]{1,64}\z/', $uuid) || !preg_match('/^[a-z0-9_]{1,24}\z/', $etype)
        || !Util::validSyncStamp($uat)) {
        continue;
    }
    $deleted = !empty($r['deleted']);
    $blob = (array_key_exists('blob', $r) && $r['blob'] !== null) ? $r['blob'] : null;
    if ($blob !== null && (!is_string($blob) || strlen($blob) > 2 * 1024 * 1024 || !preg_match('/^[0-9a-f]*\z/', $blob))) {
        continue;
    }
    $up->execute([
        ':uid'     => $c['user_id'],
        ':profile' => $profile,
        ':uuid'    => $uuid,
        ':etype'   => $etype,
        ':uat'     => $uat,
        ':deleted' => $deleted ? 1 : 0,
        // A deletion is stored without a blob, even if one came with it.
        ':blob'    => $deleted ? null : $blob,
        ':rev'     => $delta->nextRev(),
    ]);
    $delta->noted($uuid, $uat, $up->rowCount());
    $accepted++;
}

$usedQ->execute([$c['user_id']]);
$usedAfter = $usedQ->fetch();
if ((int) $usedAfter['n'] > $MAX_ROWS && (int) $usedAfter['n'] > (int) $usedBefore['n']) {
    $db->rollBack();
    $dropEmptyCounter();
    $audit->log($c['user_id'], $c['email'], $ip, 'sync', false, "profile=$profile too_many_rows");
    Util::sendError(507, 'quota_exceeded',
        "Cloud record limit reached ($MAX_ROWS per account). Delete a profile from the cloud, then sync again.");
}
if (intdiv((int) $usedAfter['hex'], 2) > $QUOTA_BYTES && (int) $usedAfter['hex'] > (int) $usedBefore['hex']) {
    $db->rollBack();
    $dropEmptyCounter();
    $audit->log($c['user_id'], $c['email'], $ip, 'sync', false, "profile=$profile quota_exceeded");
    Util::sendError(507, 'quota_exceeded',
        "Cloud storage limit reached ($quotaText per account). Remove some items, or delete a profile from the cloud, then sync again.");
}

$delta->finish();

if ($delta->isDelta()) {
    $rows = $delta->rows();
} else {
    $sel = $db->prepare(
        'SELECT uuid, entity_type, updated_at, deleted, `blob`
           FROM sync_records
          WHERE user_id = ? AND profile = ? AND updated_at > ?
          ORDER BY updated_at'
    );
    // A client whose delta couldn't be served gets everything, whatever
    // watermark it sent.
    $sel->execute([$c['user_id'], $profile, array_key_exists('since_rev', $body) ? '' : $since]);
    $rows = $sel->fetchAll();
}

$out = [];
foreach ($rows as $r) {
    $rec = [
        'uuid'        => $r['uuid'],
        'entity_type' => $r['entity_type'],
        'updated_at'  => $r['updated_at'],
        'deleted'     => (bool) (int) $r['deleted'],
    ];
    if ($r['blob'] !== null) {
        $rec['blob'] = $r['blob'];
    }
    $out[] = $rec;
}

// The label, for a profile that holds records (a label alone mustn't be a way
// to add rows without limit).
if ($name !== '') {
    $db->prepare(
        'INSERT INTO sync_profiles (user_id, profile, name)
         SELECT ?, ?, ? FROM DUAL
          WHERE EXISTS (SELECT 1 FROM sync_records WHERE user_id = ? AND profile = ?)
         ON DUPLICATE KEY UPDATE name = VALUES(name)'
    )->execute([$c['user_id'], $profile, $name, $c['user_id'], $profile]);
}

$db->commit();
$audit->log($c['user_id'], $c['email'], $ip, 'sync', true,
    "profile=$profile push=$accepted pull=" . count($out) . ($delta->isDelta() ? ' delta' : ''));
Util::sendJson(200, ['records' => $out] + $delta->meta());
