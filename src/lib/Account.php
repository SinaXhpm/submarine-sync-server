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
     * rows (with their address).
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
            $db->prepare('SELECT id FROM users WHERE id = ? FOR UPDATE')->execute([$uid]);
            $db->prepare('SELECT rev FROM sync_revs WHERE user_id = ? FOR UPDATE')->execute([$uid]);
            $owned = $db->prepare('SELECT share_id FROM shared_profiles WHERE owner_user_id = ?');
            $owned->execute([$uid]);
            $ownedIds = $owned->fetchAll(PDO::FETCH_COLUMN);
            foreach ($ownedIds as $sid) {
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
            $db->prepare('UPDATE shared_records SET last_writer = NULL WHERE last_writer = ?')->execute([$uid]);
            foreach (['sync_records', 'sync_revs', 'sync_profiles', 'user_keys', 'auth_tokens', 'auth_events'] as $t) {
                $db->prepare("DELETE FROM `$t` WHERE user_id = ?")->execute([$uid]);
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
