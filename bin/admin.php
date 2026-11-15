<?php
// Submarine sync server — admin tasks from the command line.
//
//   php bin/admin.php invite <email>       make an account and a code to finish it in the app
//   php bin/admin.php reset-code <email>   a code to choose a new password in the app
//   php bin/admin.php list [text]          accounts (all, or those whose email has the text)
//   php bin/admin.php suspend <email>      stop the account (and sign it out)
//   php bin/admin.php unsuspend <email>
//   php bin/admin.php signout <email>      sign the account out on every device
//   php bin/admin.php delete <email>       delete the account and everything it holds
//   php bin/admin.php hash-password        make SUBMARINE_ADMIN_PASSWORD_HASH for the web panel
//   php bin/admin.php check                the settings, the database and what is switched on
//
// With Docker:  docker compose exec app php bin/admin.php <command> ...

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

$root = dirname(__DIR__);
require $root . '/src/lib/Bootstrap.php';

use Submarine\Lib\Admin;
use Submarine\Lib\Audit;
use Submarine\Lib\Bootstrap;
use Submarine\Lib\Config;

Bootstrap::registerAutoload();

$args = array_slice($argv, 1);
$cmd  = (string) array_shift($args);
$yes  = false;
$args = array_values(array_filter($args, function ($a) use (&$yes) {
    if ($a === '--yes') { $yes = true; return false; }
    return true;
}));

function out(string $s = ''): void { echo $s, "\n"; }
function fail(string $s, int $code = 1): never { fwrite(STDERR, $s . "\n"); exit($code); }
function duration(int $s): string
{
    if ($s % 86400 === 0) return ($s / 86400) . ' day' . ($s === 86400 ? '' : 's');
    if ($s % 3600 === 0) return ($s / 3600) . ' hour' . ($s === 3600 ? '' : 's');
    return intdiv($s, 60) . ' minutes';
}
/** A line typed at the terminal, without showing it when $hidden. */
function ask(string $prompt, bool $hidden = false): string
{
    fwrite(STDOUT, $prompt);
    $tty = $hidden && DIRECTORY_SEPARATOR === '/' && function_exists('posix_isatty') && @posix_isatty(STDIN);
    if ($tty) shell_exec('stty -echo');
    $line = fgets(STDIN);
    if ($tty) { shell_exec('stty echo'); fwrite(STDOUT, "\n"); }
    return rtrim((string) $line, "\r\n");
}

$usage = <<<TXT
Usage: php bin/admin.php <command> [arguments]

  invite <email>       Make an account and a code the person enters in the app
                       ("Have a verify token?"), then they choose a password.
  reset-code <email>   A code for "Already have a reset token?" in the app.
  list [text]          Accounts, newest first.
  suspend <email>      Stop the account and sign it out everywhere.
  unsuspend <email>    Let it sign in again.
  signout <email>      Sign the account out on every device.
  delete <email>       Delete the account and everything it holds (asks first;
                       --yes to skip the question).
  hash-password        Make the password hash for the web admin panel.
  check                Check the settings and the database.

TXT;

if ($cmd === '' || $cmd === 'help' || $cmd === '--help' || $cmd === '-h') {
    echo $usage;
    exit($cmd === '' ? 2 : 0);
}

if ($cmd === 'hash-password') {
    $pw = ask('Admin password (12 characters or more): ', true);
    if (strlen($pw) < 12) fail('The password needs 12 characters or more.');
    if ($pw !== ask('Repeat it: ', true)) fail('The two do not match.');
    $hash = password_hash($pw, PASSWORD_DEFAULT);
    out();
    out('Put this line in your .env file (keep the single quotes):');
    out();
    out("SUBMARINE_ADMIN_PASSWORD_HASH='$hash'");
    out();
    out("or in config.php:  'admin' => ['password_hash' => '$hash'],");
    exit(0);
}

try {
    ['config' => $config, 'db' => $db] = Bootstrap::cli($root);
} catch (Throwable $e) {
    fail($e->getMessage());
}
$admin = new Admin($db, $config, new Audit($db), 'cli');

$needEmail = static function () use ($args): string {
    $e = trim((string) ($args[0] ?? ''));
    if ($e === '') fail('Give the email address.');
    return $e;
};
$account = static function (string $email) use ($admin): array {
    $u = $admin->find($email);
    if (!$u) fail("There is no account for $email.");
    return $u;
};

try {
    switch ($cmd) {
        case 'invite':
            $r = $admin->invite($needEmail());
            out("Invitation for {$r['email']}. Give them this code (it works once, for " . duration($r['ttl']) . '):');
            out();
            out('    ' . $r['code']);
            out();
            out('In Submarine: Cloud sync > "Sync server: Change" to this server > "Have a verify token? Continue verifying",');
            out('paste the code, then choose a password.');
            break;

        case 'reset-code':
            $r = $admin->resetCode($needEmail());
            out("Reset code for {$r['email']} (it works once, for " . duration($r['ttl']) . '):');
            out();
            out('    ' . $r['code']);
            out();
            out('In Submarine: Cloud sync > Sign in > "Forgot password?" > "Already have a reset token? Continue",');
            out('paste the code and choose a new password. Every device of the account is signed out.');
            break;

        case 'list':
            $q = (string) ($args[0] ?? '');
            $rows = $admin->list($q, 500);
            if (!$rows) { out('No accounts.'); break; }
            printf("%-6s %-40s %-9s %-19s %-16s %8s %10s\n", 'id', 'email', 'status', 'created', 'last seen (UTC)', 'profiles', 'storage');
            foreach ($rows as $u) {
                $seen = max((int) $u['last_seen'], (int) $u['last_login']);
                printf("%-6d %-40s %-9s %-19s %-16s %8d %10s\n", $u['id'], mb_strimwidth($u['email'], 0, 40, '…'),
                    $u['status'] === 'banned' ? 'suspended' : $u['status'], $u['created'],
                    $seen ? gmdate('Y-m-d H:i', $seen) : '-', $u['profiles'], number_format($u['bytes'] / 1024, 1) . ' KB');
            }
            $total = $admin->count($q);
            if ($total > count($rows)) out("... and " . ($total - count($rows)) . ' more.');
            break;

        case 'suspend':
            $u = $account($needEmail());
            $admin->suspend($u['id']);
            out("Suspended {$u['email']} and signed it out everywhere.");
            break;

        case 'unsuspend':
            $u = $account($needEmail());
            $admin->unsuspend($u['id']);
            out("{$u['email']} can sign in again.");
            break;

        case 'signout':
            $u = $account($needEmail());
            $n = $admin->signOut($u['id']);
            out("Signed {$u['email']} out ($n device" . ($n === 1 ? '' : 's') . ').');
            break;

        case 'delete':
            $u = $account($needEmail());
            if (!$yes) {
                $typed = ask("This deletes {$u['email']} and everything it holds on this server, for good.\nType the email again to go on: ");
                if (strtolower(trim($typed)) !== strtolower($u['email'])) fail('Not deleted.');
            }
            $admin->delete($u['id']);
            out("Deleted {$u['email']}.");
            break;

        case 'check':
            out('Settings: OK');
            $tables = $db->query('SHOW TABLES')->fetchAll(PDO::FETCH_COLUMN);
            $want = ['users', 'auth_tokens', 'verify_tokens', 'rate_limits', 'auth_events', 'sync_records', 'sync_revs',
                     'sync_profiles', 'user_keys', 'shared_profiles', 'profile_members', 'shared_records', 'shared_revs',
                     'deleted_shares', 'admin_sessions'];
            $missingTables = array_diff($want, $tables);
            out('Database: ' . ($missingTables ? 'tables missing (run php bin/migrate.php): ' . implode(', ', $missingTables) : 'OK'));
            out('Sign-up: ' . ($config['signup'] === 'open' ? 'open (anyone, code by mail)' : 'by invitation (php bin/admin.php invite <email>)'));
            out('Mail: ' . ($config['mail']['transport'] === 'off' ? 'off' : $config['mail']['transport'] . ' from ' . $config['mail']['from_address']));
            out('Web admin panel: ' . ($config['admin']['password_hash'] !== '' ? 'on, at ' . $config['base_path'] . $config['admin']['path'] : 'off'));
            out('Trusted proxies: ' . ($config['security']['trusted_proxies'] ? implode(', ', $config['security']['trusted_proxies']) . ' (' . $config['security']['client_ip_header'] . ')' : 'none'));
            // The addresses requests came from lately, as the server sees them
            // (after the trusted-proxy step). Behind a proxy that isn't
            // trusted, nearly everything comes from the proxy's own address.
            $st = $db->prepare("SELECT SUBSTRING(bucket, 11) AS addr, SUM(hits) AS n FROM rate_limits
                                 WHERE bucket LIKE 'global:ip:%' AND window_start >= ? GROUP BY bucket ORDER BY n DESC LIMIT 5");
            $st->execute([time() - 3600]);
            $seen = $st->fetchAll();
            if (!$seen) {
                out('Client addresses: no requests in the last hour.');
            } else {
                out('Client addresses in the last hour: ' . implode(', ', array_map(fn ($r) => $r['addr'] . ' (' . $r['n'] . ')', $seen)));
                $top = (string) $seen[0]['addr'];
                $total = array_sum(array_map(fn ($r) => (int) $r['n'], $seen));
                $isPrivate = !filter_var(preg_replace('#/64$#', '', $top), FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
                if ($isPrivate && count($seen) <= 2 && (int) $seen[0]['n'] >= 0.8 * $total) {
                    out("  Most requests come from $top. If that is a reverse proxy in front of the server, add it to");
                    out('  SUBMARINE_TRUSTED_PROXIES, or every user shares its rate limits.');
                }
            }
            $hash = password_hash('measure', PASSWORD_DEFAULT);
            $t0 = microtime(true);
            for ($i = 0; $i < 3; $i++) password_verify('measure x', $hash);
            $ms = (int) round((microtime(true) - $t0) / 3 * 1000);
            $floor = (int) $config['limits']['login_fail_floor_ms'];
            out("Password check: $ms ms here; failed sign-ins are answered at $floor ms"
                . ($ms > $floor - 200 ? '. RAISE limits.login_fail_floor_ms to about ' . (int) (ceil(($ms + 300) / 100) * 100) . ' ms, or the time of an answer can tell whether an email has an account.' : '.'));
            break;

        default:
            fwrite(STDERR, "Unknown command: $cmd\n\n" . $usage);
            exit(2);
    }
} catch (InvalidArgumentException $e) {
    fail($e->getMessage());
}
