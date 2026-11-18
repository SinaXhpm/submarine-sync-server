<?php
// Submarine sync server — clean-up. Run it once an hour:
//
//   php bin/cron.php          one pass, then exit (for crontab or cPanel's Cron Jobs)
//   php bin/cron.php --loop   a pass every hour, for ever (the Docker "cron" service)
//
// It removes expired sign-ins and codes, pending accounts that never finished
// signing up, old rate-limit counters, old event log rows and old admin
// sessions. Command line only.

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

$root = dirname(__DIR__);
require $root . '/src/lib/Bootstrap.php';

use Submarine\Lib\Bootstrap;

$loop = in_array('--loop', $argv, true);

$pass = static function () use ($root): int {
    try {
        ['config' => $config, 'db' => $db] = Bootstrap::cli($root);
    } catch (Throwable $e) {
        fwrite(STDERR, '[cron] ' . $e->getMessage() . "\n");
        return 1;
    }
    // One pass at a time, also across containers or hosts.
    if ((int) $db->query("SELECT GET_LOCK('submarine_cron', 0)")->fetchColumn() !== 1) {
        echo "[cron] another pass is running; skipped\n";
        return 0;
    }
    $now = time();
    $l = $config['limits'];
    $report = [];
    $run = static function (string $label, string $sql, array $args) use ($db, &$report): void {
        $st = $db->prepare($sql);
        $st->execute($args);
        $report[] = "$label: " . $st->rowCount();
    };
    try {
        $run('expired sign-ins', 'DELETE FROM auth_tokens WHERE expires_at < ?', [$now]);
        $run('expired codes', 'DELETE FROM verify_tokens WHERE expires_at < ?', [$now]);
        $run('used codes over a week old', 'DELETE FROM verify_tokens WHERE used_at IS NOT NULL AND used_at < ?', [$now - 7 * 86400]);
        // An account that never chose a password (sign-up or invitation not
        // finished). Its codes go with it (ON DELETE CASCADE).
        $run('unfinished accounts', 'DELETE FROM users WHERE status = "pending" AND password_hash IS NULL AND created_at < FROM_UNIXTIME(?)',
            [$now - (int) $l['pending_user_max_age']]);
        $run('old rate-limit counters', 'DELETE FROM rate_limits WHERE window_start < ?', [$now - (int) $l['rate_limit_retain_seconds']]);
        $run('old event log rows', 'DELETE FROM auth_events WHERE created_at < ?', [$now - (int) $l['audit_retain_seconds']]);
        // Failures that belong to no account (unknown tokens, codes, emails):
        // anyone can make those, so they are kept a shorter time.
        // In batches of 5000, each its own statement, so a large backlog
        // never holds its locks for long.
        $anon = $db->prepare('DELETE FROM auth_events WHERE user_id IS NULL AND success = 0 AND created_at < ? LIMIT 5000');
        $gone = 0;
        for ($batch = 0; $batch < 200; $batch++) {
            $anon->execute([$now - (int) $l['audit_anon_retain_seconds']]);
            $gone += $anon->rowCount();
            if ($anon->rowCount() < 5000) break;
        }
        $report[] = "old failures of no account: $gone";
        $run('old admin sessions', 'DELETE FROM admin_sessions WHERE seen_at < ?', [$now - 86400]);
        // Rows that outlived their share: a deleted share's id can never be
        // used again, so a record, counter or membership that still names one
        // (a push or an invitation that crossed the deletion) is of no use to
        // anyone. The join starts from deleted_shares and finds the rows by
        // their primary key, so this doesn't read the record tables through.
        $left = 0;
        foreach (['shared_records', 'shared_revs', 'profile_members'] as $t) {
            $st = $db->prepare("DELETE t FROM `$t` t JOIN deleted_shares d ON d.share_id = t.share_id");
            $st->execute();
            $left += $st->rowCount();
        }
        $report[] = "rows of deleted shares: $left";
    } catch (Throwable $e) {
        fwrite(STDERR, '[cron] ' . $e->getMessage() . "\n");
        return 1;
    } finally {
        $db->query("SELECT RELEASE_LOCK('submarine_cron')");
    }
    echo '[cron ' . gmdate('Y-m-d H:i') . ' UTC] ' . implode(', ', $report) . "\n";
    return 0;
};

if (!$loop) {
    exit($pass());
}
while (true) {
    $pass();
    sleep(3600);
}
