<?php
// Submarine sync server — event log: one row per sign-in, sync, share change
// or admin action. Never the contents of a profile. bin/cron.php removes rows
// older than limits.audit_retain_seconds (90 days by default).

declare(strict_types=1);

namespace Submarine\Lib;

use PDO;

final class Audit
{
    public function __construct(private PDO $db)
    {
    }

    public function log(?int $userId, ?string $email, string $ip, string $event, bool $success = true, ?string $detail = null): void
    {
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
