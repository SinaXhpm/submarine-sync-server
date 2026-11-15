<?php
declare(strict_types=1);

namespace Submarine\Lib;

use PDO;

/**
 * Delta sync (2026-10-14), shared by POST /sync and POST /shares/sync.
 *
 * Every write to a partition's records (a personal profile in sync_records, a
 * share in shared_records) takes the next value of that partition's revision
 * counter (sync_revs / shared_revs), and the row keeps the revision of the
 * write that last changed it. A client that sends the `since_rev` and `epoch`
 * from its last answer gets only the rows changed since then — not the ones
 * it just wrote, but the server's copy of anything it sent that the server
 * already held newer. Clients that don't send them (released apps) get the
 * full answer exactly as before.
 *
 * The counter row is locked (SELECT ... FOR UPDATE) for the whole exchange,
 * so exchanges on one partition run one after another: a revision is never
 * seen before an earlier one has committed. The epoch is random per counter
 * row and changes when the partition is deleted and made again; an answer to
 * a stale epoch, or to a revision past the counter, is a full one marked
 * `full: true`, so the client pushes and pulls everything again.
 */
final class SyncDelta
{
    /** uuid => updated_at of rows this exchange wrote (the client has them). */
    private array $written = [];
    /** uuid => updated_at the client sent that the server didn't take. */
    private array $kept = [];
    private int $start = 0;
    private int $rev = 0;
    private string $epoch = '';
    private bool $exists = false;

    /**
     * @param array<string,mixed> $key  partition key columns => values
     */
    private function __construct(
        private PDO $db,
        private string $revTable,
        private string $recTable,
        private array $key,
        private ?int $sinceRev,
        private string $sinceEpoch,
    ) {
    }

    /**
     * Make the partition's counter row if it is written to now or already
     * holds records. Called BEFORE the exchange's transaction: an insert and a
     * lock in one transaction could deadlock two first syncs of a partition.
     * A new counter starts at the highest revision the partition's rows carry
     * (0 for rows from before delta sync), so no older row ever looks newer
     * than a cursor it hands out.
     *
     * Plain reads only (no INSERT ... SELECT): that would take shared locks on
     * the record rows it reads, and deadlock with an exchange that holds the
     * counter and is writing them.
     */
    public static function ensure(PDO $db, string $revTable, string $recTable, array $key, bool $writing): void
    {
        $cols  = array_keys($key);
        $where = implode(' AND ', array_map(fn($c) => "$c = ?", $cols));
        $vals  = array_values($key);
        $have = $db->prepare("SELECT 1 FROM $revTable WHERE $where");
        $have->execute($vals);
        if ($have->fetchColumn() !== false) {
            return;
        }
        $max = $db->prepare("SELECT COUNT(*), COALESCE(MAX(rev), 0) FROM $recTable WHERE $where");
        $max->execute($vals);
        [$rows, $top] = $max->fetch(PDO::FETCH_NUM);
        if (!$writing && (int) $rows === 0) {
            return; // a pull of nothing: no counter for it
        }
        $db->prepare(
            "INSERT IGNORE INTO $revTable (" . implode(', ', $cols) . ", rev, epoch)
             VALUES (" . implode(', ', array_fill(0, count($cols), '?')) . ", ?, ?)"
        )->execute([...$vals, (int) $top, bin2hex(random_bytes(8))]);
    }

    /** Inside the transaction: lock the counter and read the client's cursor. */
    public static function open(PDO $db, string $revTable, string $recTable, array $key, array $body): self
    {
        $since = $body['since_rev'] ?? null;
        $sinceRev = (is_int($since) && $since >= 0) ? $since : null;
        $epoch = $body['epoch'] ?? '';
        $d = new self($db, $revTable, $recTable, $key, $sinceRev, is_string($epoch) ? $epoch : '');
        $st = $db->prepare("SELECT rev, epoch FROM $revTable WHERE {$d->where()} FOR UPDATE");
        $st->execute(array_values($key));
        $row = $st->fetch(PDO::FETCH_ASSOC);
        if ($row) {
            $d->exists = true;
            $d->start = $d->rev = (int) $row['rev'];
            $d->epoch = (string) $row['epoch'];
        }
        return $d;
    }

    private function where(): string
    {
        return implode(' AND ', array_map(fn($c) => "$c = ?", array_keys($this->key)));
    }

    /** The revision for the next write. */
    public function nextRev(): int
    {
        return ++$this->rev;
    }

    /**
     * What came of writing one record the client sent. A write that changed
     * nothing gives its revision back, so the counter only moves with real
     * changes (writes run one by one under the lock).
     */
    public function noted(string $uuid, string $updatedAt, int $affectedRows): void
    {
        if ($affectedRows > 0) {
            $this->written[$uuid] = $updatedAt;
            unset($this->kept[$uuid]);
        } else {
            $this->rev--;
            $this->kept[$uuid] = $updatedAt;
        }
    }

    /** Store the counter, before the commit. */
    public function finish(): void
    {
        if ($this->exists && $this->rev !== $this->start) {
            $this->db->prepare("UPDATE $this->revTable SET rev = ? WHERE {$this->where()}")
                ->execute([$this->rev, ...array_values($this->key)]);
        }
    }

    /** The client asked for the changes since a revision it may have. */
    private function asked(): bool
    {
        return $this->sinceRev !== null;
    }

    /** ...and can have them: same epoch, a revision the counter has reached. */
    public function isDelta(): bool
    {
        return $this->asked() && $this->exists && hash_equals($this->epoch, $this->sinceEpoch) && $this->sinceRev <= $this->start;
    }

    /**
     * The rows for a delta answer: changed since the client's revision, minus
     * what this exchange wrote from it, plus the server's copy of what it sent
     * stale. Only when isDelta().
     */
    public function rows(): array
    {
        $cols = 'uuid, entity_type, updated_at, deleted, `blob`';
        $st = $this->db->prepare("SELECT $cols FROM $this->recTable WHERE {$this->where()} AND rev > ? ORDER BY rev");
        $st->execute([...array_values($this->key), $this->sinceRev]);
        $out = [];
        foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $r) {
            if (isset($this->written[$r['uuid']])) {
                continue;
            }
            $out[$r['uuid']] = $r;
        }
        if ($this->kept) {
            $one = $this->db->prepare("SELECT $cols FROM $this->recTable WHERE {$this->where()} AND uuid = ?");
            foreach ($this->kept as $uuid => $sent) {
                if (isset($out[$uuid])) {
                    continue;
                }
                $one->execute([...array_values($this->key), $uuid]);
                $r = $one->fetch(PDO::FETCH_ASSOC);
                if ($r && strcmp((string) $r['updated_at'], (string) $sent) > 0) {
                    $out[$uuid] = $r;
                }
            }
        }
        return array_values($out);
    }

    /**
     * Deleting a partition: inside its transaction, first lock the counter
     * (exchanges lock it first too, so the two can't deadlock), and at the end
     * drop it, so the partition's next counter has a new epoch and every
     * client starts over. No counter table yet (a database that never ran a
     * delta exchange): nothing to do.
     */
    public static function lockForDelete(PDO $db, string $revTable, array $key): void
    {
        self::tolerateMissing(function () use ($db, $revTable, $key) {
            $where = implode(' AND ', array_map(fn($c) => "$c = ?", array_keys($key)));
            $db->prepare("SELECT rev FROM $revTable WHERE $where FOR UPDATE")->execute(array_values($key));
        });
    }

    public static function forget(PDO $db, string $revTable, array $key): void
    {
        self::tolerateMissing(function () use ($db, $revTable, $key) {
            $where = implode(' AND ', array_map(fn($c) => "$c = ?", array_keys($key)));
            $db->prepare("DELETE FROM $revTable WHERE $where")->execute(array_values($key));
        });
    }

    private static function tolerateMissing(callable $fn): void
    {
        try {
            $fn();
        } catch (\PDOException $e) {
            if ($e->getCode() !== '42S02') {
                throw $e;
            }
        }
    }

    /** What the answer adds: the cursor, and `full` when a delta wasn't possible. */
    public function meta(): array
    {
        $m = [];
        if ($this->exists) {
            $m['rev'] = $this->rev;
            $m['epoch'] = $this->epoch;
        }
        if ($this->asked() && !$this->isDelta()) {
            $m['full'] = true;
        }
        return $m;
    }
}
