<?php
// Submarine sync server — event log: one row per sign-in, sync, share change
// or admin action. Never the contents of a profile. bin/cron.php removes rows
// older than limits.audit_retain_seconds (90 days by default).

declare(strict_types=1);

namespace Submarine\Lib;

use PDO;

final class Audit
{
    /**
     * Failed requests that belong to no account (unknown tokens and codes,
     * unknown emails) are logged at most this many times an hour per address:
     * anyone can make them as fast as the rate limits allow, and a row each
     * would fill the disk. The rate limits themselves still count every one.
     */
    public const ANON_FAILURES_PER_HOUR = 60;

    /** $rl: given for web requests, so the cap above applies; the command line logs everything. */
    public function __construct(private PDO $db, private ?RateLimit $rl = null)
    {
    }

    public function log(?int $userId, ?string $email, string $ip, string $event, bool $success = true, ?string $detail = null): void
    {
        if ($userId === null && !$success && $this->rl !== null
            && $this->rl->hit('audit:anon:' . Util::rateKeyIp($ip), 3600) > self::ANON_FAILURES_PER_HOUR) {
            return;
        }
        $this->db->prepare(
            'INSERT INTO auth_events (user_id, email, ip_address, event, success, detail, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)'
        )->execute([
            $userId,
            $email !== null ? mb_substr($email, 0, 191) : null,
            mb_substr($ip, 0, 45),
            mb_substr($event, 0, 32),
            $success ? 1 : 0,
            $detail !== null ? mb_substr($detail, 0, 255) : null,
            time(),
        ]);
    }
}
