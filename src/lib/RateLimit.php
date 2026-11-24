<?php
// Submarine sync server — fixed-window rate limiter kept in the database.
//
// No Redis or APCu needed, so it runs on shared hosting too. One indexed row
// per bucket and window; bin/cron.php removes old windows.

declare(strict_types=1);

namespace Submarine\Lib;

use PDO;

final class RateLimit
{
    public function __construct(private PDO $db)
    {
    }

    /** Count one hit in the bucket's current window; returns the new count. */
    public function hit(string $bucket, int $windowSeconds): int
    {
        // The count this hit made, read in the same statement (LAST_INSERT_ID
        // is per connection). Read again after it, it would include hits made
        // meanwhile, and at one moment all of them could see themselves past
        // the limit.
        $this->db->prepare(
            'INSERT INTO rate_limits (bucket, window_start, hits) VALUES (?, ?, LAST_INSERT_ID(1))
             ON DUPLICATE KEY UPDATE hits = LAST_INSERT_ID(hits + 1)'
        )->execute([$this->key($bucket), $this->windowStart($windowSeconds)]);
        return (int) $this->db->query('SELECT LAST_INSERT_ID()')->fetchColumn();
    }

    /** Count a hit; past `max` in the window, answer 429 and stop. */
    public function enforce(string $bucket, int $max, int $windowSeconds): void
    {
        if ($this->hit($bucket, $windowSeconds) > $max) {
            // The bucket isn't named: it can hold an email or an address.
            header('Retry-After: ' . (string) $windowSeconds);
            Util::sendError(429, 'rate_limited', 'Too many requests, slow down');
        }
    }

    /** Hits in the bucket over the last `windowSeconds`, without counting one. */
    public function count(string $bucket, int $windowSeconds): int
    {
        $st = $this->db->prepare(
            'SELECT COALESCE(SUM(hits), 0) FROM rate_limits WHERE bucket = ? AND window_start >= ?'
        );
        $st->execute([$this->key($bucket), $this->windowStart($windowSeconds)]);
        return (int) $st->fetchColumn();
    }

    public function reset(string $bucket): void
    {
        $this->db->prepare('DELETE FROM rate_limits WHERE bucket = ?')->execute([$this->key($bucket)]);
    }

    /**
     * The bucket as it is stored. The column holds 191 characters and some
     * buckets carry a whole email address; past 120 characters the name is
     * cut and ends in a hash of the whole of it, so two long names don't
     * share a bucket.
     */
    private function key(string $bucket): string
    {
        return strlen($bucket) <= 120 ? $bucket : substr($bucket, 0, 55) . '#' . hash('sha256', $bucket);
    }

    private function windowStart(int $windowSeconds): int
    {
        return intdiv(time(), $windowSeconds) * $windowSeconds;
    }
}
