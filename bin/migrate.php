<?php
// Submarine sync server — make or bring up to date the database tables.
//
//   php bin/migrate.php            check the settings, then create what is missing
//   php bin/migrate.php --wait=60  first wait up to 60 s for the database (Docker)
//
// Safe to run any number of times. The Docker image runs it at every start.

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

$root = dirname(__DIR__);
require $root . '/src/lib/Bootstrap.php';

use Submarine\Lib\Bootstrap;
use Submarine\Lib\Config;

Bootstrap::registerAutoload();
$wait = 0;
foreach (array_slice($argv, 1) as $arg) {
    if (preg_match('/^--wait=(\d+)$/', $arg, $m)) {
        $wait = (int) $m[1];
    } else {
        fwrite(STDERR, "Unknown option: $arg\n");
        exit(2);
    }
}

$missing = Bootstrap::missingRequirements();
if ($missing) {
    fwrite(STDERR, implode("\n", $missing) . "\n");
    exit(1);
}
try {
    $config = Config::load($root);
} catch (Throwable $e) {
    fwrite(STDERR, 'config.php: ' . $e->getMessage() . "\n");
    exit(1);
}
$problems = Config::problems($config);
if ($problems) {
    fwrite(STDERR, "The settings need attention:\n  - " . implode("\n  - ", $problems) . "\n");
    exit(1);
}

$deadline = time() + $wait;
while (true) {
    try {
        $db = Bootstrap::connect($config);
        break;
    } catch (PDOException $e) {
        if (time() >= $deadline) {
            fwrite(STDERR, 'Could not connect to the database: ' . $e->getMessage() . "\n");
            exit(1);
        }
        sleep(2);
    }
}

$sql = (string) file_get_contents($root . '/schema.sql');
$sql = (string) preg_replace('/^\s*--.*$/m', '', $sql);
$done = 0;
foreach (preg_split('/;\s*(?:\r?\n|$)/', $sql) as $stmt) {
    $stmt = trim($stmt);
    if ($stmt === '') continue;
    $db->exec($stmt);
    $done++;
}
// Changes to tables an older version made. Each step looks first, so running
// it again does nothing.
$name = (string) $db->query('SELECT DATABASE()')->fetchColumn();
$column = static function (string $table, string $col) use ($db, $name): array {
    $st = $db->prepare('SELECT COLUMN_TYPE, COLLATION_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? AND COLUMN_NAME = ?');
    $st->execute([$name, $table, $col]);
    return $st->fetch() ?: [];
};
$changed = [];
// 1. Invitation codes are a kind of their own.
if (!str_contains((string) ($column('verify_tokens', 'purpose')['COLUMN_TYPE'] ?? ''), "'invite'")) {
    $db->exec("ALTER TABLE verify_tokens MODIFY purpose ENUM('verify','invite','claim','reset','login') NOT NULL");
    $changed[] = 'verify_tokens.purpose';
}
// 2. Ids and stamps compare byte by byte ("Work" and "work" are two profiles,
//    and updated_at sorts the way PHP's strcmp does).
foreach (['sync_records', 'sync_revs', 'user_keys', 'profile_members', 'shared_records', 'shared_revs', 'deleted_shares'] as $t) {
    $st = $db->prepare('SELECT TABLE_COLLATION FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?');
    $st->execute([$name, $t]);
    if ((string) $st->fetchColumn() !== 'ascii_bin') {
        $db->exec("ALTER TABLE `$t` CONVERT TO CHARACTER SET ascii COLLATE ascii_bin");
        $changed[] = $t;
    }
}
if (($column('sync_profiles', 'profile')['COLLATION_NAME'] ?? '') !== 'ascii_bin') {
    $db->exec('ALTER TABLE sync_profiles MODIFY profile VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL');
    $changed[] = 'sync_profiles.profile';
}
if (($column('shared_profiles', 'share_id')['COLLATION_NAME'] ?? '') !== 'ascii_bin') {
    $db->exec('ALTER TABLE shared_profiles MODIFY share_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL');
    $changed[] = 'shared_profiles.share_id';
}
// 3. Account deletion finds the records a user wrote last into others' shares
//    (and its update of them must use this index: src/lib/Account.php).
$idx = $db->prepare('SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? AND INDEX_NAME = ?');
$idx->execute([$name, 'shared_records', 'idx_writer']);
if ((int) $idx->fetchColumn() === 0) {
    $db->exec('ALTER TABLE shared_records ADD INDEX idx_writer (last_writer)');
    $changed[] = 'shared_records.idx_writer';
}

$tables = $db->query('SHOW TABLES')->fetchAll(PDO::FETCH_COLUMN);
echo "Database ready: $done statements run, " . count($tables) . ' tables'
    . ($changed ? '; updated: ' . implode(', ', $changed) : '') . ".\n";
