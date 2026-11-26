<?php
// Submarine sync server — what is done to an account as a whole. Used by the
// app's own account deletion (POST /auth/delete-account), the admin panel and
// bin/admin.php, so a table added later is added here once.

declare(strict_types=1);

namespace Submarine\Lib;

use PDO;
use Throwable;

final class Account
{
    /**
     * Deletes a user and everything held for them: the sync partitions and
     * their revision counters, the sharing key, the sign-ins and the event log
     * rows (their own, and the ones that name only their address).
     *
     * Shares the user owns go for every member (nobody is left to manage
     * them), and their ids can't be taken again. Their memberships in other
     * people's shares go. What they wrote into other people's shares stays,
     * with no writer named: those records belong to the share.
     *
     * One transaction: either everything of the user is gone or nothing is.
     */
    public static function delete(PDO $db, int $uid): void
    {
        $db->beginTransaction();
        try {
            // Locks in the order the other paths take them: the account's row
            // (sync, shares/create), its profiles' revision counters (sync),
            // the counters of the shares it owns (shares/sync, shares/delete),
            // and only then the share rows. Taken the other way round, a sync
            // running at the same moment could deadlock with this.
            $u = $db->prepare('SELECT email FROM users WHERE id = ? FOR UPDATE');
            $u->execute([$uid]);
            $email = $u->fetchColumn();
            $db->prepare('SELECT rev FROM sync_revs WHERE user_id = ? FOR UPDATE')->execute([$uid]);
            $owned = $db->prepare('SELECT share_id FROM shared_profiles WHERE owner_user_id = ?');
            $owned->execute([$uid]);
            $ownedIds = $owned->fetchAll(PDO::FETCH_COLUMN);
            // The counters of every share this touches: the ones it owns, and
            // the ones whose records name it as their last writer (cleared
            // below; idx_writer finds them). Locked in one sorted order, as a
            // share's sync locks its counter before its records.
            $w = $db->prepare('SELECT DISTINCT share_id FROM shared_records WHERE last_writer = ?');
            $w->execute([$uid]);
            $touched = array_values(array_unique(array_map('strval', array_merge($ownedIds, $w->fetchAll(PDO::FETCH_COLUMN)))));
            sort($touched, SORT_STRING);
            foreach ($touched as $sid) {
                $db->prepare('SELECT rev FROM shared_revs WHERE share_id = ? FOR UPDATE')->execute([$sid]);
            }
            foreach ($ownedIds as $sid) {
                foreach (['shared_records', 'shared_revs', 'profile_members', 'shared_profiles'] as $t) {
                    $db->prepare("DELETE FROM `$t` WHERE share_id = ?")->execute([$sid]);
                }
                $db->prepare('INSERT IGNORE INTO deleted_shares (share_id, deleted_at) VALUES (?, ?)')
                   ->execute([$sid, time()]);
            }
            $db->prepare('DELETE FROM profile_members WHERE member_user_id = ?')->execute([$uid]);
            // The id could be given to someone else after a database restart.
            $db->prepare('UPDATE shared_records FORCE INDEX (idx_writer) SET last_writer = NULL WHERE last_writer = ?')->execute([$uid]);
            foreach (['sync_records', 'sync_revs', 'sync_profiles', 'user_keys', 'auth_tokens', 'auth_events'] as $t) {
                $db->prepare("DELETE FROM `$t` WHERE user_id = ?")->execute([$uid]);
            }
            // Log rows that name the address but no account: a mail to it
            // that failed or was held back, a sign-in tried before the
            // account was there. Found by a plain read and deleted by their
            // key: a delete by the address would lock a gap in that index
            // for other addresses' rows too.
            if (is_string($email)) {
                $rows = $db->prepare('SELECT id FROM auth_events WHERE email = ? AND user_id IS NULL');
                $rows->execute([$email]);
                $drop = $db->prepare('DELETE FROM auth_events WHERE id = ?');
                foreach ($rows->fetchAll(PDO::FETCH_COLUMN) as $id) {
                    $drop->execute([$id]);
                }
            }
            // verify_tokens go with the user row (ON DELETE CASCADE).
            $db->prepare('DELETE FROM users WHERE id = ?')->execute([$uid]);
            $db->commit();
        } catch (Throwable $e) {
            if ($db->inTransaction()) {
                $db->rollBack();
            }
            throw $e;
        }
    }
}
