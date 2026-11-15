<?php
// Submarine sync server — start-up: settings, class loading, the database.

declare(strict_types=1);

namespace Submarine\Lib;

use PDO;
use PDOException;

final class Bootstrap
{
    public const MIN_PHP = 80100;

    /** Class loader for Submarine\Lib\Foo => src/lib/Foo.php. No Composer needed. */
    public static function registerAutoload(): void
    {
        static $done = false;
        if ($done) return;
        $done = true;
        spl_autoload_register(static function (string $class): void {
            $prefix = 'Submarine\\Lib\\';
            if (strncmp($class, $prefix, strlen($prefix)) !== 0) return;
            $name = substr($class, strlen($prefix));
            if (!preg_match('/^[A-Za-z]+$/', $name)) return;
            $file = __DIR__ . '/' . $name . '.php';
            if (is_file($file)) require $file;
        });
    }

    /**
     * Everything a web request needs. Refuses to answer (500, details in the
     * server log only) when PHP or the settings aren't right.
     *
     * @return array{config: array, db: PDO, rl: RateLimit, audit: Audit, auth: Auth, mailer: Mailer, ip: string}
     */
    public static function web(string $root): array
    {
        // Whatever the host's php.ini says: errors go to the log, never into
        // an answer.
        ini_set('display_errors', '0');
        ini_set('display_startup_errors', '0');
        ini_set('log_errors', '1');
        umask(0027);
        self::registerAutoload();
        $missing = self::missingRequirements();
        if ($missing) {
            error_log('[submarine] ' . implode(' ', $missing));
            Util::sendError(500, 'misconfigured', 'The server is not set up correctly; its log says why.');
        }
        try {
            $config = Config::load($root);
        } catch (\Throwable $e) {
            error_log('[submarine] config: ' . $e->getMessage());
            Util::sendError(500, 'misconfigured', 'The server is not set up correctly; its log says why.');
        }
        $problems = Config::problems($config);
        if ($problems) {
            foreach ($problems as $line) error_log('[submarine] config: ' . $line);
            Util::sendError(500, 'misconfigured', 'The server is not set up correctly; its log says why.');
        }
        $db = self::openDb($config);
        $rl     = new RateLimit($db);
        $audit  = new Audit($db);
        $auth   = new Auth($db, $rl, $audit, $config);
        $mailer = new Mailer($config, $audit);
        $ip     = Util::clientIp($config);
        return compact('config', 'db', 'rl', 'audit', 'auth', 'mailer', 'ip');
    }

    /** The same for the command line: errors are thrown, not answered. */
    public static function cli(string $root): array
    {
        self::registerAutoload();
        $missing = self::missingRequirements();
        if ($missing) {
            throw new \RuntimeException(implode("\n", $missing));
        }
        $config = Config::load($root);
        $problems = Config::problems($config);
        if ($problems) {
            throw new \RuntimeException("The settings need attention:\n  - " . implode("\n  - ", $problems));
        }
        $db = self::connect($config);
        return ['config' => $config, 'db' => $db];
    }

    /** @return string[] */
    public static function missingRequirements(): array
    {
        $out = [];
        if (PHP_VERSION_ID < self::MIN_PHP) {
            $out[] = 'PHP 8.1 or newer is needed (this is ' . PHP_VERSION . ').';
        }
        foreach (['pdo_mysql', 'json', 'mbstring', 'zlib', 'openssl'] as $ext) {
            if (!extension_loaded($ext)) {
                $out[] = "The PHP extension '$ext' is needed.";
            }
        }
        return $out;
    }

    public static function connect(array $config): PDO
    {
        $d = $config['db'];
        $dsn = sprintf('mysql:host=%s;port=%d;dbname=%s;charset=%s', $d['host'], (int) $d['port'], $d['name'], $d['charset'] ?? 'utf8mb4');
        $db = new PDO($dsn, (string) $d['user'], (string) $d['password'], [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
            PDO::ATTR_TIMEOUT            => 5,
        ]);
        // The queries write text in double quotes ("active"), which a server
        // set to ANSI_QUOTES would read as column names.
        $modes = explode(',', (string) $db->query('SELECT @@SESSION.sql_mode')->fetchColumn());
        $keep = array_filter($modes, static fn ($m) => $m !== '' && $m !== 'ANSI_QUOTES' && $m !== 'ANSI');
        if (count($keep) !== count($modes)) {
            $db->prepare('SET SESSION sql_mode = ?')->execute([implode(',', $keep)]);
        }
        return $db;
    }

    private static function openDb(array $config): PDO
    {
        try {
            return self::connect($config);
        } catch (PDOException $e) {
            error_log('[submarine] database connection failed: ' . $e->getMessage());
            Util::sendError(503, 'db_unavailable', 'The database is not reachable.');
        }
    }
}
