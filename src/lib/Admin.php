<?php
// Submarine sync server — the admin's actions on accounts, shared by the
// command line (bin/admin.php) and the web panel (src/admin-panel.php).
//
// Metadata only: emails, status, sizes and times. Nothing here reads or shows
// what is inside a profile; the records are encrypted on the devices, and
// their keys never reach the server.

declare(strict_types=1);

namespace Submarine\Lib;

use InvalidArgumentException;
use PDO;

final class Admin
{
    public function __construct(private PDO $db, private array $config, private Audit $audit, private string $actorIp)
    {
    }

    private function normEmail(string $email): string
    {
        $email = strtolower(trim($email));
        if (!Util::validEmail($email)) {
            throw new InvalidArgumentException('That is not an email address the server takes.');
        }
        return $email;
    }

    /** @return array{id:int,email:string,status:string}|null */
    public function find(string $email): ?array
    {
        $st = $this->db->prepare('SELECT id, email, status FROM users WHERE email = ?');
        $st->execute([strtolower(trim($email))]);
        $row = $st->fetch();
        return $row ? ['id' => (int) $row['id'], 'email' => (string) $row['email'], 'status' => (string) $row['status']] : null;
    }

    public function byId(int $id): ?array
    {
        $st = $this->db->prepare('SELECT id, email, status FROM users WHERE id = ?');
        $st->execute([$id]);
        $row = $st->fetch();
        return $row ? ['id' => (int) $row['id'], 'email' => (string) $row['email'], 'status' => (string) $row['status']] : null;
    }

    private function newCode(int $uid, string $purpose, int $ttl): string
    {
        $code = Util::randomToken(24);
        $this->db->prepare('INSERT INTO verify_tokens (token_hash, user_id, purpose, expires_at) VALUES (?, ?, ?, ?)')
            ->execute([Util::hashToken($code, $this->config['security']['token_pepper']), $uid, $purpose, time() + $ttl]);
        return $code;
    }

    /**
     * An invitation: a pending account (made now if needed) and a verify code
     * for it. The person enters the code in the app ("Have a verify token?"),
     * then chooses their password. No mail is involved.
     *
     * @return array{code:string,ttl:int,email:string}
     */
    public function invite(string $email): array
    {
        $email = $this->normEmail($email);
        $ttl = (int) $this->config['limits']['invite_token_ttl'];
        $this->db->beginTransaction();
        try {
            $st = $this->db->prepare('SELECT id, status FROM users WHERE email = ? FOR UPDATE');
            $st->execute([$email]);
            $row = $st->fetch();
            if ($row && $row['status'] === 'active') {
                throw new InvalidArgumentException("$email already has an account. To let them set a new password, make a reset code.");
            }
            if ($row && $row['status'] === 'banned') {
                throw new InvalidArgumentException("$email is suspended. Unsuspend it first.");
            }
            if ($row) {
                $uid = (int) $row['id'];
            } else {
                $this->db->prepare('INSERT INTO users (email, status) VALUES (?, "pending")')->execute([$email]);
                $uid = (int) $this->db->lastInsertId();
            }
            // Only the newest invitation works. It is a code of its own kind
            // ("invite"), so a sign-up with the same address (open sign-up)
            // doesn't cancel it.
            $this->db->prepare('DELETE FROM verify_tokens WHERE user_id = ? AND purpose = "invite"')->execute([$uid]);
            // A pending account is cleaned up after pending_user_max_age; an
            // invitation starts that time again.
            $this->db->prepare('UPDATE users SET created_at = NOW() WHERE id = ?')->execute([$uid]);
            $code = $this->newCode($uid, 'invite', $ttl);
            $this->db->commit();
        } catch (\Throwable $e) {
            if ($this->db->inTransaction()) $this->db->rollBack();
            throw $e;
        }
        $this->audit->log($uid, $email, $this->actorIp, 'admin_invite', true);
        return ['code' => $code, 'ttl' => $ttl, 'email' => $email];
    }

    /**
     * A password reset code for an active account, for when mail is off or
     * didn't arrive. The person enters it in the app ("Already have a reset
     * token?") and sets a new password; every device is signed out then.
     *
     * @return array{code:string,ttl:int,email:string}
     */
    public function resetCode(string $email): array
    {
        $email = $this->normEmail($email);
        $u = $this->find($email);
        if (!$u) {
            throw new InvalidArgumentException("There is no account for $email.");
        }
        if ($u['status'] !== 'active') {
            throw new InvalidArgumentException("$email is {$u['status']}: a reset code is only for an active account" . ($u['status'] === 'pending' ? ' (make an invitation instead).' : '.'));
        }
        $ttl = (int) $this->config['limits']['verify_token_ttl'];
        $code = $this->newCode($u['id'], 'reset', $ttl);
        $this->audit->log($u['id'], $email, $this->actorIp, 'admin_reset_code', true);
        return ['code' => $code, 'ttl' => $ttl, 'email' => $email];
    }

    public function suspend(int $uid): void
    {
        $u = $this->mustExist($uid);
        $this->db->prepare('UPDATE users SET status = "banned" WHERE id = ?')->execute([$uid]);
        $this->db->prepare('DELETE FROM auth_tokens WHERE user_id = ?')->execute([$uid]);
        $this->audit->log($uid, $u['email'], $this->actorIp, 'admin_suspend', true);
    }

    public function unsuspend(int $uid): void
    {
        $u = $this->mustExist($uid);
        if ($u['status'] !== 'banned') {
            throw new InvalidArgumentException("{$u['email']} is not suspended.");
        }
        // Back to active only with a password; otherwise it was still pending.
        $st = $this->db->prepare('SELECT password_hash IS NOT NULL FROM users WHERE id = ?');
        $st->execute([$uid]);
        $status = (int) $st->fetchColumn() === 1 ? 'active' : 'pending';
        $this->db->prepare('UPDATE users SET status = ? WHERE id = ?')->execute([$status, $uid]);
        $this->audit->log($uid, $u['email'], $this->actorIp, 'admin_unsuspend', true);
    }

    /** Signs the account out on every device; returns how many sign-ins ended. */
    public function signOut(int $uid): int
    {
        $u = $this->mustExist($uid);
        $st = $this->db->prepare('DELETE FROM auth_tokens WHERE user_id = ?');
        $st->execute([$uid]);
        $this->audit->log($uid, $u['email'], $this->actorIp, 'admin_signout', true, 'tokens=' . $st->rowCount());
        return $st->rowCount();
    }

    public function delete(int $uid): string
    {
        $u = $this->mustExist($uid);
        Account::delete($this->db, $uid);
        // Logged without the address: the account is gone.
        $this->audit->log(null, null, $this->actorIp, 'admin_delete', true, "uid=$uid");
        return $u['email'];
    }

    private function mustExist(int $uid): array
    {
        $u = $uid > 0 ? $this->byId($uid) : null;
        if (!$u) {
            throw new InvalidArgumentException('There is no such account.');
        }
        return $u;
    }

    /**
     * Accounts, newest first, with what they hold. `$q` filters by a part of
     * the email.
     *
     * @return array<int, array{id:int,email:string,status:string,created:string,last_login:?int,last_seen:?int,profiles:int,bytes:int}>
     */
    public function list(string $q = '', int $limit = 50, int $offset = 0): array
    {
        [$where, $args] = $this->filter($q);
        $limit = max(1, min(500, $limit));
        $offset = max(0, $offset);
        $st = $this->db->prepare(
            "SELECT id, email, status, created_at, last_login_at FROM users $where ORDER BY id DESC LIMIT $limit OFFSET $offset"
        );
        $st->execute($args);
        $users = $st->fetchAll();
        if (!$users) return [];
        $ids = array_map(fn($u) => (int) $u['id'], $users);
        $in = implode(',', array_fill(0, count($ids), '?'));

        $store = [];
        $s = $this->db->prepare(
            "SELECT user_id, COUNT(DISTINCT profile) AS profiles, COALESCE(SUM(LENGTH(`blob`)), 0) AS hex
               FROM sync_records WHERE user_id IN ($in) GROUP BY user_id"
        );
        $s->execute($ids);
        foreach ($s->fetchAll() as $r) {
            $store[(int) $r['user_id']] = [(int) $r['profiles'], intdiv((int) $r['hex'], 2)];
        }
        $seen = [];
        $s = $this->db->prepare("SELECT user_id, MAX(last_used_at) AS seen FROM auth_tokens WHERE user_id IN ($in) GROUP BY user_id");
        $s->execute($ids);
        foreach ($s->fetchAll() as $r) {
            $seen[(int) $r['user_id']] = $r['seen'] !== null ? (int) $r['seen'] : null;
        }

        $out = [];
        foreach ($users as $u) {
            $id = (int) $u['id'];
            $out[] = [
                'id'         => $id,
                'email'      => (string) $u['email'],
                'status'     => (string) $u['status'],
                'created'    => (string) $u['created_at'],
                'last_login' => $u['last_login_at'] !== null ? (int) $u['last_login_at'] : null,
                'last_seen'  => $seen[$id] ?? null,
                'profiles'   => $store[$id][0] ?? 0,
                'bytes'      => $store[$id][1] ?? 0,
            ];
        }
        return $out;
    }

    public function count(string $q = ''): int
    {
        [$where, $args] = $this->filter($q);
        $st = $this->db->prepare("SELECT COUNT(*) FROM users $where");
        $st->execute($args);
        return (int) $st->fetchColumn();
    }

    private function filter(string $q): array
    {
        $q = trim($q);
        if ($q === '') return ['', []];
        $like = '%' . str_replace(['\\', '%', '_'], ['\\\\', '\\%', '\\_'], mb_substr($q, 0, 190)) . '%';
        return ['WHERE email LIKE ?', [$like]];
    }

    /** The numbers for the top of the panel. */
    public function totals(): array
    {
        $by = ['active' => 0, 'pending' => 0, 'banned' => 0];
        foreach ($this->db->query('SELECT status, COUNT(*) AS n FROM users GROUP BY status')->fetchAll() as $r) {
            $by[(string) $r['status']] = (int) $r['n'];
        }
        $personal = $this->db->query(
            'SELECT COUNT(*) AS profiles, COALESCE(SUM(hex), 0) AS hex, COALESCE(SUM(n), 0) AS records FROM (
                SELECT COUNT(*) AS n, SUM(LENGTH(`blob`)) AS hex FROM sync_records GROUP BY user_id, profile) t'
        )->fetch();
        $shared = $this->db->query(
            'SELECT (SELECT COUNT(*) FROM shared_profiles) AS shares,
                    (SELECT COALESCE(SUM(LENGTH(`blob`)), 0) FROM shared_records) AS hex,
                    (SELECT COUNT(*) FROM shared_records) AS records'
        )->fetch();
        return [
            'accounts'   => $by,
            'profiles'   => (int) $personal['profiles'],
            'shares'     => (int) $shared['shares'],
            'records'    => (int) $personal['records'] + (int) $shared['records'],
            'bytes'      => intdiv((int) $personal['hex'] + (int) $shared['hex'], 2),
        ];
    }
}
