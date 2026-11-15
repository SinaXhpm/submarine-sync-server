<?php
// /keys/* and /shares/*  [auth] — sharing a profile with other accounts.
//
// The server never sees a profile's key or contents:
//   - public_key is public by definition.
//   - wrapped_privkey is the account's X25519 private key, encrypted with a
//     key made from the user's separate sharing passphrase, which never
//     reaches the server.
//   - a profile's data key reaches the server only sealed to a member's
//     public key (sealed_dek).
//
// Runs inside src/api.php's try{} with $db, $auth, $rl, $audit, $config, $ip,
// $method and $path in scope.

if (!defined('SUBMARINE_API')) {
    // Requested as a file of its own rather than through public/index.php.
    http_response_code(404);
    exit;
}

$c = $auth->requireAuth($ip);
[$uMax, $uWindow] = $config['limits']['rate_user_global'];
$rl->enforce("user:{$c['user_id']}:global", $uMax, $uWindow);

// A deleted share's id is kept (deleted_shares) so that nobody can register it
// again. Without this, a former member who knows the id could re-create it as
// its owner and invite the old members' devices into a share sealed to a key
// they hold.
$share_deleted = static function (PDO $db, string $shareId): bool {
    $st = $db->prepare('SELECT 1 FROM deleted_shares WHERE share_id = ?');
    $st->execute([$shareId]);
    return $st->fetchColumn() !== false;
};

/**
 * My membership row for a share, or false. Returns role, status, sealed_dek.
 */
$share_role = static function (PDO $db, string $shareId, int $uid) {
    $st = $db->prepare(
        'SELECT role, status, sealed_dek FROM profile_members
          WHERE share_id = ? AND member_user_id = ?'
    );
    $st->execute([$shareId, $uid]);
    return $st->fetch();
};

// --------------------------------------------------------------------------
// POST /keys/publish  — publish (or restore-on-new-device) my identity key.
// --------------------------------------------------------------------------
if ($method === 'POST' && $path === '/keys/publish') {
    $body = \Submarine\Lib\Util::readJson(256 * 1024);
    $pub  = \Submarine\Lib\Util::str($body, 'public_key');
    $wpk  = \Submarine\Lib\Util::str($body, 'wrapped_privkey');
    $salt = \Submarine\Lib\Util::str($body, 'enc_salt');
    // NB: PCRE caps {n,m} at 65535, so bound wrapped_privkey's length with
    // strlen, not a huge quantifier (which would fail to COMPILE → always 400).
    if (!preg_match('/^[0-9a-f]{64}\z/', $pub)
        || !preg_match('/^[0-9a-f]+\z/', $wpk) || strlen($wpk) < 2 || strlen($wpk) > 100000
        || !preg_match('/^[0-9a-f]{2,64}\z/', $salt)) {
        \Submarine\Lib\Util::sendError(400, 'invalid_input',
            'public_key (32-byte hex), wrapped_privkey (hex), enc_salt (hex) required');
    }
    // Idempotent upsert, gated by account auth. Changing the public key is
    // allowed (e.g. the user reset a forgotten encryption passphrase and had to
    // regenerate), but it's a real event: a new key can't open grants sealed to
    // the OLD key, so the rotation flow (S4) is responsible for re-sealing every
    // grant to the new key. We record a distinct audit event when the public key
    // actually changes so there's a trail of any identity rotation.
    $st = $db->prepare('SELECT public_key, wrapped_privkey, enc_salt FROM user_keys WHERE user_id = ?');
    $st->execute([$c['user_id']]);
    $had     = $st->fetch();
    $prev    = $had === false ? false : (string) $had['public_key'];
    $rotated = ($prev !== false && $prev !== $pub);
    $given   = \Submarine\Lib\Util::str($body, 'current_password');
    // A password check here is the account's password, so it has the same
    // cap as signing in from one account: 5 tries an hour, counted before the
    // check (parallel tries can't slip past the lockout).
    $checkPassword = static function () use ($rl, $auth, $audit, $c, $ip, $given): void {
        $rl->enforce("keys-password:user:{$c['user_id']}", 5, 3600);
        if (!$auth->confirmPassword((int) $c['user_id'], $given)) {
            $audit->log($c['user_id'], $c['email'], $ip, 'keys_replace_denied', false, $given === '' ? 'no_password' : 'bad_password');
            \Submarine\Lib\Util::sendError(403, 'reauth_required',
                'Setting your sharing key needs your account password (current_password).');
        }
    };
    if ($had !== false) {
        if ((string) $had['public_key'] === $pub && (string) $had['wrapped_privkey'] === $wpk
            && (string) $had['enc_salt'] === $salt) {
            // The same key again (a retry): nothing changes, nothing is asked.
            \Submarine\Lib\Util::sendJson(200, ['ok' => true, 'created' => false, 'rotated' => false]);
        }
        // Replacing a key that is already published (a new key, or the same
        // one wrapped differently) takes the account password, not only a
        // token: whoever holds a stolen token must not be able to swap the key
        // that everything shared with this account is sealed to. A wrong
        // password counts as a failed login (Auth::confirmPassword).
        $checkPassword();
    } elseif ($given !== '' || !empty($config['security']['keys_need_password'])) {
        // The first key: checked when the app sends the password (or when the
        // server requires it). Released apps send only the token here; see
        // README, Security, for what that leaves open and how to close it.
        $checkPassword();
    }
    if ($had === false) {
        // A plain insert: two first publishes at once can't both win, and the
        // second can't overwrite the first without the password.
        try {
            $db->prepare('INSERT INTO user_keys (user_id, public_key, wrapped_privkey, enc_salt, updated_at) VALUES (?, ?, ?, ?, ?)')
               ->execute([$c['user_id'], $pub, $wpk, $salt, time()]);
        } catch (\PDOException $e) {
            if ($e->getCode() !== '23000') throw $e;
            \Submarine\Lib\Util::sendError(409, 'key_exists', 'A sharing key was set up at the same moment. Try again.');
        }
        $audit->log($c['user_id'], $c['email'], $ip, 'keys_publish', true, $given !== '' ? 'new password_checked' : 'new');
        // Whoever owns the mailbox hears about it, when mail is on: a key set
        // up with a stolen token doesn't go unnoticed.
        if ($mailer->enabled()) {
            \Submarine\Lib\Util::sendJsonThenContinue(200, ['ok' => true, 'created' => true, 'rotated' => false]);
            $mailer->sendKeyNotice((string) $c['email'], $ip);
            exit;
        }
        \Submarine\Lib\Util::sendJson(200, ['ok' => true, 'created' => true, 'rotated' => false]);
    }
    $db->prepare('UPDATE user_keys SET public_key = ?, wrapped_privkey = ?, enc_salt = ?, updated_at = ? WHERE user_id = ?')
       ->execute([$pub, $wpk, $salt, time(), $c['user_id']]);
    $audit->log($c['user_id'], $c['email'], $ip, $rotated ? 'keys_rotate' : 'keys_publish', true, 'update');
    \Submarine\Lib\Util::sendJson(200, ['ok' => true, 'created' => false, 'rotated' => $rotated]);
}

// --------------------------------------------------------------------------
// GET /keys/me  — fetch my own key material to restore on a new device.
// --------------------------------------------------------------------------
if ($method === 'GET' && $path === '/keys/me') {
    $st = $db->prepare('SELECT public_key, wrapped_privkey, enc_salt FROM user_keys WHERE user_id = ?');
    $st->execute([$c['user_id']]);
    $row = $st->fetch();
    if (!$row) {
        \Submarine\Lib\Util::sendJson(200, ['exists' => false]);
    }
    \Submarine\Lib\Util::sendJson(200, [
        'exists'          => true,
        'public_key'      => $row['public_key'],
        'wrapped_privkey' => $row['wrapped_privkey'],
        'enc_salt'        => $row['enc_salt'],
    ]);
}

// --------------------------------------------------------------------------
// POST /keys/lookup  — resolve an email to its public key, to share with it.
// POST (not GET) so the email isn't logged in the query string.
// --------------------------------------------------------------------------
if ($method === 'POST' && $path === '/keys/lookup') {
    $body  = \Submarine\Lib\Util::readJson(4096);
    $email = strtolower(trim(\Submarine\Lib\Util::str($body, 'email')));
    if (!\Submarine\Lib\Util::validEmail($email)) {
        \Submarine\Lib\Util::sendError(400, 'invalid_input', 'valid email required');
    }
    // Join users→user_keys. A uniform 404 for "no such user" and "user hasn't
    // published a key" so this endpoint can't enumerate registered emails.
    $st = $db->prepare(
        'SELECT u.id AS uid, u.email AS email, k.public_key AS public_key
           FROM users u
           JOIN user_keys k ON k.user_id = u.id
          WHERE u.email = ? AND u.status = "active"'
    );
    $st->execute([$email]);
    $row = $st->fetch();
    // An answer still says whether an address has a key here, so one account
    // gets 60 an hour. Looking up someone it already shares a profile with is
    // free: replacing a share's key after a member leaves looks up every
    // member left, and that must not run out halfway.
    $coMember = false;
    if ($row) {
        $co = $db->prepare(
            'SELECT 1 FROM profile_members a
               JOIN profile_members b ON b.share_id = a.share_id
              WHERE a.member_user_id = ? AND b.member_user_id = ?
              LIMIT 1'
        );
        $co->execute([$c['user_id'], (int) $row['uid']]);
        $coMember = $co->fetchColumn() !== false;
    }
    if (!$coMember) {
        $rl->enforce("user:{$c['user_id']}:lookup", 60, 3600);
    }
    if (!$row) {
        \Submarine\Lib\Util::sendError(404, 'not_found', 'No shareable account for that email');
    }
    \Submarine\Lib\Util::sendJson(200, [
        'user_id'    => (int) $row['uid'],
        'email'      => $row['email'],
        'public_key' => $row['public_key'],
    ]);
}

// ==========================================================================
// /shares/*  — a shared profile + its members. share_id is a client-minted
// hex id (like an entity uuid). The DEK is opaque to the server throughout:
// every sealed_dek is a sealed box only the target member's private key opens.
// ==========================================================================

// -------- POST /shares/create — turn a local profile into a shared one. -----
if ($method === 'POST' && $path === '/shares/create') {
    $body = \Submarine\Lib\Util::readJson(256 * 1024);
    $sid  = \Submarine\Lib\Util::str($body, 'share_id');
    // Other members see this name. Control characters and the ones that
    // flip text direction are taken out, so a name can't pass itself off as
    // something else on screen (ZWNJ, used in Persian, stays).
    $name = trim((string) preg_replace('/[\p{Cc}\x{061C}\x{200E}\x{200F}\x{202A}-\x{202E}\x{2066}-\x{2069}]/u', '',
        \Submarine\Lib\Util::str($body, 'name')));
    $sdek = \Submarine\Lib\Util::str($body, 'sealed_dek');
    if (!preg_match('/^[0-9a-f]{16,64}\z/', $sid)) {
        \Submarine\Lib\Util::sendError(400, 'invalid_input', 'share_id (16-64 hex) required');
    }
    if ($name === '' || mb_strlen($name) > 64) {
        \Submarine\Lib\Util::sendError(400, 'invalid_input', 'name (1-64 chars) required');
    }
    if (!preg_match('/^[0-9a-f]+\z/', $sdek) || strlen($sdek) < 2 || strlen($sdek) > 100000) {
        \Submarine\Lib\Util::sendError(400, 'invalid_input', 'sealed_dek (hex) required');
    }
    // Two tries: a deadlock (40001), or a row changed after this
    // transaction's first read (1020: MariaDB's innodb_snapshot_isolation, on
    // by default from 11.6; the share's deletion, for one), rolls everything
    // back and is tried once more; a second one answers 503, never a 500.
    for ($try = 1; ; $try++) {
    try {
    $db->beginTransaction();
    // One create at a time per account (the share cap below). Only the
    // account's row is locked, never a share row that may not exist yet: a lock
    // on a missing key is a gap lock, and two accounts holding one each
    // deadlock as soon as both insert.
    $lockMe = $db->prepare('SELECT id FROM users WHERE id = ? FOR UPDATE');
    $lockMe->execute([$c['user_id']]);
    if ($lockMe->fetchColumn() === false) {
        // The account was deleted meanwhile.
        $db->rollBack();
        \Submarine\Lib\Util::sendError(401, 'invalid_token', 'Unknown token');
    }
    // A deleted id stays deleted. A plain read, without a lock: a locking
    // read of an id that isn't there would be a gap lock again.
    if ($share_deleted($db, $sid)) {
        $db->rollBack();
        \Submarine\Lib\Util::sendError(410, 'share_deleted', 'This shared profile was deleted; share the profile again to get a new one.');
    }
    $ex = $db->prepare('SELECT owner_user_id FROM shared_profiles WHERE share_id = ?');
    $ex->execute([$sid]);
    $owner = $ex->fetchColumn();
    if ($owner !== false) {
        // The share exists: its row is locked while ownership is decided. If
        // its owner deleted it meanwhile (the deletion held the row), it is
        // gone once the lock is ours.
        $lk = $db->prepare('SELECT owner_user_id FROM shared_profiles WHERE share_id = ? FOR UPDATE');
        $lk->execute([$sid]);
        $owner = $lk->fetchColumn();
        if ($owner === false) {
            $db->rollBack();
            \Submarine\Lib\Util::sendError(410, 'share_deleted', 'This shared profile was deleted; share the profile again to get a new one.');
        }
    }
    if ($owner !== false && (int) $owner !== (int) $c['user_id']) {
        $db->rollBack();
        \Submarine\Lib\Util::sendError(409, 'share_exists', 'share_id already taken');
    }
    // Each share has its own storage, so the number one account can own is
    // capped too (far above real use: nobody owns more than one today).
    $MAX_SHARES = (int) $config['quota']['shares'];
    if ($owner === false) {
        $owned = $db->prepare('SELECT COUNT(*) FROM shared_profiles WHERE owner_user_id = ?');
        $owned->execute([$c['user_id']]);
        if ((int) $owned->fetchColumn() >= $MAX_SHARES) {
            $db->rollBack();
            \Submarine\Lib\Util::sendError(507, 'quota_exceeded',
                "Shared profile limit reached ($MAX_SHARES per account). Delete one you no longer use, then share again.");
        }
    }
    if ($owner === false) {
        // A plain insert: if another account made the same id at the same
        // moment, this one fails here, before it can become an owner.
        try {
            $db->prepare('INSERT INTO shared_profiles (share_id, owner_user_id, name, created_at) VALUES (?, ?, ?, ?)')
               ->execute([$sid, $c['user_id'], $name, time()]);
        } catch (\PDOException $e) {
            // A deadlock has already ended the transaction on the server.
            if ($db->inTransaction()) {
                $db->rollBack();
            }
            if ($e->getCode() !== '23000') throw $e;
            \Submarine\Lib\Util::sendError(409, 'share_exists', 'share_id already taken');
        }
    } else {
        $db->prepare('UPDATE shared_profiles SET name = ? WHERE share_id = ? AND owner_user_id = ?')
           ->execute([$name, $sid, $c['user_id']]);
    }
    $db->prepare(
        'INSERT INTO profile_members (share_id, member_user_id, role, sealed_dek, status, invited_by, created_at)
         VALUES (?, ?, "owner", ?, "active", ?, ?)
         ON DUPLICATE KEY UPDATE sealed_dek = VALUES(sealed_dek), role = "owner", status = "active"'
    )->execute([$sid, $c['user_id'], $sdek, $c['user_id'], time()]);
    $db->commit();
    break;
    } catch (\PDOException $e) {
        if ($db->inTransaction()) {
            $db->rollBack();
        }
        if ($e->getCode() !== '40001' && (int) ($e->errorInfo[1] ?? 0) !== 1020) {
            throw $e;
        }
        if ($try >= 2) {
            header('Retry-After: 1');
            \Submarine\Lib\Util::sendError(503, 'busy', 'The server was busy; try again.');
        }
        usleep(random_int(20000, 80000));
    }
    }
    $audit->log($c['user_id'], $c['email'], $ip, 'share_create', true, "share=$sid");
    \Submarine\Lib\Util::sendJson(200, ['ok' => true, 'share_id' => $sid]);
}

// -------- POST /shares/invite — owner adds a member (pending). --------------
if ($method === 'POST' && $path === '/shares/invite') {
    $body  = \Submarine\Lib\Util::readJson(256 * 1024);
    $sid   = \Submarine\Lib\Util::str($body, 'share_id');
    $email = strtolower(trim(\Submarine\Lib\Util::str($body, 'email')));
    $role  = \Submarine\Lib\Util::str($body, 'role');
    $sdek  = \Submarine\Lib\Util::str($body, 'sealed_dek');
    if (!preg_match('/^[0-9a-f]{16,64}\z/', $sid) || !\Submarine\Lib\Util::validEmail($email)
        || !in_array($role, ['editor', 'user'], true)
        || !preg_match('/^[0-9a-f]+\z/', $sdek) || strlen($sdek) < 2 || strlen($sdek) > 100000) {
        \Submarine\Lib\Util::sendError(400, 'invalid_input', 'share_id, email, role (editor|user), sealed_dek required');
    }
    $me = $share_role($db, $sid, (int) $c['user_id']);
    if (!$me || $me['role'] !== 'owner') {
        \Submarine\Lib\Util::sendError(403, 'forbidden', 'only the share owner can invite');
    }
    $u = $db->prepare('SELECT id FROM users WHERE email = ? AND status = "active"');
    $u->execute([$email]);
    $inviteeId = $u->fetchColumn();
    // Like a lookup, an invite says whether an address has an account, and
    // each one lands in somebody's list: 60 an hour. Re-inviting someone
    // already on this share is free: that's how the share's key is re-sealed
    // for every member after one leaves.
    $onShare = false;
    if ($inviteeId !== false) {
        $m = $db->prepare('SELECT 1 FROM profile_members WHERE share_id = ? AND member_user_id = ?');
        $m->execute([$sid, $inviteeId]);
        $onShare = $m->fetchColumn() !== false;
    }
    if (!$onShare) {
        $rl->enforce("user:{$c['user_id']}:invite", 60, 3600);
    }
    if ($inviteeId === false) {
        \Submarine\Lib\Util::sendError(404, 'not_found', 'No shareable account for that email');
    }
    if ((int) $inviteeId === (int) $c['user_id']) {
        \Submarine\Lib\Util::sendError(400, 'invalid_input', 'you are already the owner');
    }
    // Nobody's invite list can be flooded: at most 50 invites waiting for
    // one person (re-inviting someone already on the share is an update).
    $pending = $db->prepare(
        'SELECT COUNT(*) FROM profile_members
          WHERE member_user_id = ? AND status = "pending" AND share_id <> ?'
    );
    $pending->execute([$inviteeId, $sid]);
    if ((int) $pending->fetchColumn() >= 50) {
        \Submarine\Lib\Util::sendError(429, 'too_many_pending',
            'That person has too many invites waiting. Ask them to accept or decline some first.');
    }
    // Upsert: re-inviting updates role + sealed_dek but never downgrades an
    // already-active member back to pending (status is untouched here).
    $db->prepare(
        'INSERT INTO profile_members (share_id, member_user_id, role, sealed_dek, status, invited_by, created_at)
         VALUES (?, ?, ?, ?, "pending", ?, ?)
         ON DUPLICATE KEY UPDATE role = VALUES(role), sealed_dek = VALUES(sealed_dek), invited_by = VALUES(invited_by)'
    )->execute([$sid, $inviteeId, $role, $sdek, $c['user_id'], time()]);
    $audit->log($c['user_id'], $c['email'], $ip, 'share_invite', true, "share=$sid to=$email role=$role");
    \Submarine\Lib\Util::sendJson(200, ['ok' => true, 'member_user_id' => (int) $inviteeId]);
}

// -------- POST /shares/list — shares I'm a member of. -----------------------
// Deliberately does NOT select sealed_dek (a MEDIUMTEXT): a temp table holding
// a TEXT column is forced onto disk, and this 3-way join + sort needs a temp
// table. Fetch the DEK per-share via /shares/dek (a PK point-lookup that needs
// no temp table). Keeps list working even under tmp-disk pressure.
if ($method === 'POST' && $path === '/shares/list') {
    $st = $db->prepare(
        'SELECT m.share_id, m.role, m.status, s.name, ou.email AS owner_email
           FROM profile_members m
           JOIN shared_profiles s ON s.share_id = m.share_id
           JOIN users ou          ON ou.id = s.owner_user_id
          WHERE m.member_user_id = ?
          ORDER BY s.name
          LIMIT 1000'
    );
    $st->execute([$c['user_id']]);
    $out = [];
    foreach ($st->fetchAll() as $r) {
        $out[] = [
            'share_id'    => $r['share_id'],
            'name'        => $r['name'],
            'role'        => $r['role'],
            'status'      => $r['status'],
            'owner_email' => $r['owner_email'],
        ];
    }
    \Submarine\Lib\Util::sendJson(200, ['shares' => $out]);
}

// -------- POST /shares/dek — my sealed data-key for one share. ---------------
// PK point-lookup (share_id, member_user_id) — no join, no sort, no temp table.
if ($method === 'POST' && $path === '/shares/dek') {
    $body = \Submarine\Lib\Util::readJson(4096);
    $sid  = \Submarine\Lib\Util::str($body, 'share_id');
    if (!preg_match('/^[0-9a-f]{16,64}\z/', $sid)) {
        \Submarine\Lib\Util::sendError(400, 'invalid_input', 'share_id required');
    }
    $me = $share_role($db, $sid, (int) $c['user_id']);
    if (!$me && $share_deleted($db, $sid)) {
        \Submarine\Lib\Util::sendError(410, 'share_deleted', 'This shared profile was deleted by its owner.');
    }
    // An invite has to be accepted before its key is handed out (the app
    // accepts first; /shares/accept answers with the key itself).
    if (!$me || $me['status'] !== 'active') {
        \Submarine\Lib\Util::sendError(403, 'forbidden', 'not an active member of this share');
    }
    \Submarine\Lib\Util::sendJson(200, ['role' => $me['role'], 'status' => $me['status'], 'sealed_dek' => $me['sealed_dek']]);
}

// -------- POST /shares/members — the member list for a share I belong to. ----
if ($method === 'POST' && $path === '/shares/members') {
    $body = \Submarine\Lib\Util::readJson(4096);
    $sid  = \Submarine\Lib\Util::str($body, 'share_id');
    if (!preg_match('/^[0-9a-f]{16,64}\z/', $sid)) {
        \Submarine\Lib\Util::sendError(400, 'invalid_input', 'share_id required');
    }
    // Active members only: an invitation alone (which anyone can be sent)
    // doesn't show who else is on the share.
    $me = $share_role($db, $sid, (int) $c['user_id']);
    if (!$me || $me['status'] !== 'active') {
        \Submarine\Lib\Util::sendError(403, 'forbidden', 'not an active member of this share');
    }
    $st = $db->prepare(
        'SELECT m.member_user_id, m.role, m.status, u.email
           FROM profile_members m JOIN users u ON u.id = m.member_user_id
          WHERE m.share_id = ?
          ORDER BY FIELD(m.role, "owner", "editor", "user"), u.email'
    );
    $st->execute([$sid]);
    $out = [];
    foreach ($st->fetchAll() as $r) {
        $out[] = [
            'user_id' => (int) $r['member_user_id'],
            'email'   => $r['email'],
            'role'    => $r['role'],
            'status'  => $r['status'],
        ];
    }
    \Submarine\Lib\Util::sendJson(200, ['members' => $out]);
}

// -------- POST /shares/accept — accept a pending invite. --------------------
if ($method === 'POST' && $path === '/shares/accept') {
    $body = \Submarine\Lib\Util::readJson(4096);
    $sid  = \Submarine\Lib\Util::str($body, 'share_id');
    if (!preg_match('/^[0-9a-f]{16,64}\z/', $sid)) {
        \Submarine\Lib\Util::sendError(400, 'invalid_input', 'share_id required');
    }
    $me = $share_role($db, $sid, (int) $c['user_id']);
    if (!$me) {
        \Submarine\Lib\Util::sendError(404, 'not_found', 'no invite for this share');
    }
    $db->prepare('UPDATE profile_members SET status = "active" WHERE share_id = ? AND member_user_id = ?')
       ->execute([$sid, $c['user_id']]);
    $audit->log($c['user_id'], $c['email'], $ip, 'share_accept', true, "share=$sid");
    \Submarine\Lib\Util::sendJson(200, ['ok' => true, 'role' => $me['role'], 'sealed_dek' => $me['sealed_dek']]);
}

// -------- POST /shares/sync — per-entity sync of a shared profile. ----------
// Same LWW model as personal /sync, but keyed by share_id and gated by
// membership + role: an active member may PULL; only owner/editor may PUSH.
// The server never decrypts `blob` (sealed under the shared DEK).
if ($method === 'POST' && $path === '/shares/sync') {
    // Record sets go gzipped both ways when the client does that (see Util).
    \Submarine\Lib\Util::enableCompression();
    $body    = \Submarine\Lib\Util::readJson(4 * 1024 * 1024);
    $sid     = \Submarine\Lib\Util::str($body, 'share_id');
    $since   = \Submarine\Lib\Util::str($body, 'since');
    $records = $body['records'] ?? [];
    if (!preg_match('/^[0-9a-f]{16,64}\z/', $sid)) {
        \Submarine\Lib\Util::sendError(400, 'invalid_input', 'share_id required');
    }
    if (!is_array($records)) {
        \Submarine\Lib\Util::sendError(400, 'invalid_input', 'records must be an array');
    }
    if (count($records) > 5000) {
        \Submarine\Lib\Util::sendError(413, 'too_many_records', 'max 5000 records per sync');
    }
    $me = $share_role($db, $sid, (int) $c['user_id']);
    if (!$me && $share_deleted($db, $sid)) {
        \Submarine\Lib\Util::sendError(410, 'share_deleted', 'This shared profile was deleted by its owner.');
    }
    if (!$me || $me['status'] !== 'active') {
        \Submarine\Lib\Util::sendError(403, 'forbidden', 'not an active member of this share');
    }
    // Role ACL: viewers ('user') may pull (empty push) but never write.
    if ($me['role'] === 'user' && count($records) > 0) {
        \Submarine\Lib\Util::sendError(403, 'read_only', 'your role can use this profile but not edit it');
    }

    // A share's storage has caps like an account's: quota.share_bytes of blobs
    // (stored as hex, so LENGTH/2) and quota.share_records rows, the second
    // because rows without a blob cost nothing in bytes. Checked after the
    // push, before commit, like personal /sync.
    $SHARE_QUOTA_BYTES = (int) $config['quota']['share_bytes'];
    $SHARE_MAX_ROWS    = (int) $config['quota']['share_records'];
    $usedQ = $db->prepare(
        "SELECT COUNT(*) AS n, COALESCE(SUM(LENGTH(`blob`)), 0) AS hex FROM shared_records WHERE share_id = ?"
    );

    // Delta sync: the share's revision counter, made before the transaction
    // and locked inside it for the whole exchange (src/lib/SyncDelta.php).
    $partition = ['share_id' => $sid];
    \Submarine\Lib\SyncDelta::ensure($db, 'shared_revs', 'shared_records', $partition, (bool) $records);
    $db->beginTransaction();
    $delta = \Submarine\Lib\SyncDelta::open($db, 'shared_revs', 'shared_records', $partition, $body);
    $usedQ->execute([$sid]);
    $before = $usedQ->fetch();
    $up = $db->prepare(
        "INSERT INTO shared_records (share_id, uuid, entity_type, updated_at, deleted, `blob`, last_writer, rev)
         VALUES (:sid, :uuid, :etype, :uat, :deleted, :blob, :writer, :rev)
         ON DUPLICATE KEY UPDATE
            entity_type = IF(VALUES(updated_at) > updated_at, VALUES(entity_type), entity_type),
            deleted     = IF(VALUES(updated_at) > updated_at, VALUES(deleted), deleted),
            `blob`      = IF(VALUES(updated_at) > updated_at, VALUES(`blob`), `blob`),
            last_writer = IF(VALUES(updated_at) > updated_at, VALUES(last_writer), last_writer),
            rev         = IF(VALUES(updated_at) > updated_at, VALUES(rev), rev),
            updated_at  = IF(VALUES(updated_at) > updated_at, VALUES(updated_at), updated_at)"
    );
    $accepted = 0;
    foreach ($records as $r) {
        if (!is_array($r)) {
            continue;
        }
        $uuid  = \Submarine\Lib\Util::str($r, 'uuid');
        $etype = \Submarine\Lib\Util::str($r, 'entity_type');
        $uat   = \Submarine\Lib\Util::str($r, 'updated_at');
        if ($uuid === '' || $etype === '' || $uat === ''
            || !preg_match('/^[0-9a-f]{1,64}\z/', $uuid) || !preg_match('/^[a-z0-9_]{1,24}\z/', $etype)
            || !\Submarine\Lib\Util::validSyncStamp($uat)) {
            continue;
        }
        $deleted = !empty($r['deleted']);
        $blob = (array_key_exists('blob', $r) && $r['blob'] !== null) ? $r['blob'] : null;
        if ($blob !== null && (!is_string($blob) || strlen($blob) > 2 * 1024 * 1024 || !preg_match('/^[0-9a-f]*\z/', $blob))) {
            continue;
        }
        $up->execute([
            ':sid'     => $sid,
            ':uuid'    => $uuid,
            ':etype'   => $etype,
            ':uat'     => $uat,
            ':deleted' => $deleted ? 1 : 0,
            // A deletion is stored without a blob (the app sends none).
            ':blob'    => $deleted ? null : $blob,
            ':writer'  => (int) $c['user_id'],
            ':rev'     => $delta->nextRev(),
        ]);
        $delta->noted($uuid, $uat, $up->rowCount());
        $accepted++;
    }
    $usedQ->execute([$sid]);
    $after = $usedQ->fetch();
    $overRows  = (int) $after['n'] > $SHARE_MAX_ROWS && (int) $after['n'] > (int) $before['n'];
    $overBytes = intdiv((int) $after['hex'], 2) > $SHARE_QUOTA_BYTES && (int) $after['hex'] > (int) $before['hex'];
    if ($overRows || $overBytes) {
        $db->rollBack();
        $audit->log($c['user_id'], $c['email'], $ip, 'share_sync', false,
            "share=$sid " . ($overRows ? 'too_many_rows' : 'quota_exceeded'));
        \Submarine\Lib\Util::sendError(507, 'quota_exceeded', $overRows
            ? "This shared profile is full ($SHARE_MAX_ROWS records). Remove some items, then sync again."
            : 'This shared profile is full (' . round($SHARE_QUOTA_BYTES / (1024 * 1024), 1) . ' MB). Remove some items, then sync again.');
    }
    $delta->finish();
    // What changed since the client's revision, or everything newer than its
    // watermark (released apps, a stale cursor), as in personal /sync.
    if ($delta->isDelta()) {
        $rows = $delta->rows();
    } else {
        $sel = $db->prepare(
            "SELECT uuid, entity_type, updated_at, deleted, `blob`
               FROM shared_records
              WHERE share_id = ? AND updated_at > ?
              ORDER BY updated_at"
        );
        $sel->execute([$sid, array_key_exists('since_rev', $body) ? '' : $since]);
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
    $db->commit();
    $audit->log($c['user_id'], $c['email'], $ip, 'share_sync', true, "share=$sid push=$accepted pull=" . count($out) . ($delta->isDelta() ? ' delta' : ''));
    \Submarine\Lib\Util::sendJson(200, ['records' => $out] + $delta->meta());
}

// -------- POST /shares/set-role — owner changes a member's role. ------------
if ($method === 'POST' && $path === '/shares/set-role') {
    $body   = \Submarine\Lib\Util::readJson(4096);
    $sid    = \Submarine\Lib\Util::str($body, 'share_id');
    $target = (int) ($body['member_user_id'] ?? 0);
    $role   = \Submarine\Lib\Util::str($body, 'role');
    if (!preg_match('/^[0-9a-f]{16,64}\z/', $sid) || $target <= 0 || !in_array($role, ['editor', 'user'], true)) {
        \Submarine\Lib\Util::sendError(400, 'invalid_input', 'share_id, member_user_id, role (editor|user) required');
    }
    $me = $share_role($db, $sid, (int) $c['user_id']);
    if (!$me || $me['role'] !== 'owner') {
        \Submarine\Lib\Util::sendError(403, 'forbidden', 'only the owner can change roles');
    }
    // `role != owner` guard means the owner's own role can never be demoted.
    $db->prepare('UPDATE profile_members SET role = ? WHERE share_id = ? AND member_user_id = ? AND role != "owner"')
       ->execute([$role, $sid, $target]);
    $audit->log($c['user_id'], $c['email'], $ip, 'share_set_role', true, "share=$sid uid=$target role=$role");
    \Submarine\Lib\Util::sendJson(200, ['ok' => true]);
}

// -------- POST /shares/revoke — owner removes a member. ---------------------
if ($method === 'POST' && $path === '/shares/revoke') {
    $body   = \Submarine\Lib\Util::readJson(4096);
    $sid    = \Submarine\Lib\Util::str($body, 'share_id');
    $target = (int) ($body['member_user_id'] ?? 0);
    if (!preg_match('/^[0-9a-f]{16,64}\z/', $sid) || $target <= 0) {
        \Submarine\Lib\Util::sendError(400, 'invalid_input', 'share_id, member_user_id required');
    }
    $me = $share_role($db, $sid, (int) $c['user_id']);
    if (!$me || $me['role'] !== 'owner') {
        \Submarine\Lib\Util::sendError(403, 'forbidden', 'only the owner can revoke');
    }
    if ($target === (int) $c['user_id']) {
        \Submarine\Lib\Util::sendError(400, 'invalid_input', 'the owner cannot revoke themselves');
    }
    $db->prepare('DELETE FROM profile_members WHERE share_id = ? AND member_user_id = ? AND role != "owner"')
       ->execute([$sid, $target]);
    $audit->log($c['user_id'], $c['email'], $ip, 'share_revoke', true, "share=$sid uid=$target");
    \Submarine\Lib\Util::sendJson(200, ['ok' => true]);
}

// -------- POST /shares/delete — owner deletes the whole shared profile. -----
if ($method === 'POST' && $path === '/shares/delete') {
    $body = \Submarine\Lib\Util::readJson(4096);
    $sid  = \Submarine\Lib\Util::str($body, 'share_id');
    if (!preg_match('/^[0-9a-f]{16,64}\z/', $sid)) {
        \Submarine\Lib\Util::sendError(400, 'invalid_input', 'share_id required');
    }
    $me = $share_role($db, $sid, (int) $c['user_id']);
    if (!$me || $me['role'] !== 'owner') {
        \Submarine\Lib\Util::sendError(403, 'forbidden', 'only the owner can delete a share');
    }
    $db->beginTransaction();
    // The share's revision counter is locked first, as every exchange does
    // (src/lib/SyncDelta.php), and dropped with the rest.
    \Submarine\Lib\SyncDelta::lockForDelete($db, 'shared_revs', ['share_id' => $sid]);
    $db->prepare('DELETE FROM profile_members WHERE share_id = ?')->execute([$sid]);
    $db->prepare('DELETE FROM shared_profiles WHERE share_id = ?')->execute([$sid]);
    $db->prepare('INSERT IGNORE INTO deleted_shares (share_id, deleted_at) VALUES (?, ?)')->execute([$sid, time()]);
    // Best-effort: drop the synced entities too. Wrapped in its own guard so a
    // not-yet-created shared_records table (no sync ever ran) isn't fatal.
    try {
        $db->prepare('DELETE FROM shared_records WHERE share_id = ?')->execute([$sid]);
    } catch (\Throwable $e) {
        // table may not exist yet — nothing synced; ignore.
    }
    \Submarine\Lib\SyncDelta::forget($db, 'shared_revs', ['share_id' => $sid]);
    $db->commit();
    $audit->log($c['user_id'], $c['email'], $ip, 'share_delete', true, "share=$sid");
    \Submarine\Lib\Util::sendJson(200, ['ok' => true]);
}

// -------- POST /shares/leave — a non-owner removes themselves. ---------------
if ($method === 'POST' && $path === '/shares/leave') {
    $body = \Submarine\Lib\Util::readJson(4096);
    $sid  = \Submarine\Lib\Util::str($body, 'share_id');
    if (!preg_match('/^[0-9a-f]{16,64}\z/', $sid)) {
        \Submarine\Lib\Util::sendError(400, 'invalid_input', 'share_id required');
    }
    $me = $share_role($db, $sid, (int) $c['user_id']);
    if (!$me) {
        \Submarine\Lib\Util::sendError(404, 'not_found', 'not a member');
    }
    if ($me['role'] === 'owner') {
        \Submarine\Lib\Util::sendError(400, 'invalid_input', 'the owner cannot leave; delete or transfer the share');
    }
    $db->prepare('DELETE FROM profile_members WHERE share_id = ? AND member_user_id = ?')
       ->execute([$sid, $c['user_id']]);
    \Submarine\Lib\Util::sendJson(200, ['ok' => true]);
}

// Fall through — anything under /keys/* or /shares/* we don't handle.
\Submarine\Lib\Util::sendError(404, 'not_found', 'Unknown sharing endpoint');
