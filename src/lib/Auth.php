<?php
// Submarine sync server — sign-in tokens, password checks and the lockout.

declare(strict_types=1);

namespace Submarine\Lib;

use PDO;

final class Auth
{
    /**
     * A bcrypt hash of random text that no password matches. A check that has
     * no real hash to test (no such account, no password yet, locked) tests
     * this one, so it takes as long as a real one.
     */
    public const DUMMY_PASSWORD_HASH = '$2y$12$Ul8mg3GWqYwspSW2GscX4OqUNnC0XF6oNjrnmvy8y.lBlZ/YTiSDu';

    private PDO $db;
    private RateLimit $rl;
    private Audit $audit;
    private array $config;

    public function __construct(PDO $db, RateLimit $rl, Audit $audit, array $config)
    {
        $this->db    = $db;
        $this->rl    = $rl;
        $this->audit = $audit;
        $this->config = $config;
    }

    /**
     * Validate the auth token from the incoming request. On any failure:
     * log + emit 401 + exit. On success: returns the context dict
     * { user_id, email, token } and updates `last_used_at`.
     */
    public function requireAuth(string $ip): array
    {
        // We prefer a custom `X-Auth-Token` header (raw token, no prefix)
        // over the standard `Authorization: Bearer ...` form because some
        // shared-host PHP-FPM setups + WAFs strip Authorization before it
        // reaches us. Custom X-* headers are passed through untouched on
        // every host we've tested. Authorization remains accepted as a
        // fallback for tooling that only knows Bearer.
        $token = $this->readAuthToken();
        if ($token === '') {
            Util::sendError(401, 'invalid_token', 'Missing auth token');
        }
        // Length sanity check before hitting the DB — saves a query on
        // obvious garbage.
        if (strlen($token) < 32 || strlen($token) > 128) {
            $this->audit->log(null, null, $ip, 'invalid_token', false, 'malformed');
            Util::sendError(401, 'invalid_token', 'Malformed token');
        }

        // DB stores only HMAC(token, pepper) — never the raw token. See
        // Util::hashToken for rationale.
        $tokenHash = Util::hashToken($token, $this->config['security']['token_pepper']);

        $stmt = $this->db->prepare(
            'SELECT t.user_id, t.expires_at, u.email, u.status
               FROM auth_tokens t
               JOIN users u ON u.id = t.user_id
              WHERE t.token_hash = ?'
        );
        $stmt->execute([$tokenHash]);
        $row = $stmt->fetch();
        if (!$row) {
            $this->audit->log(null, null, $ip, 'invalid_token', false, 'unknown');
            Util::sendError(401, 'invalid_token', 'Unknown token');
        }
        if ((int) $row['expires_at'] < time()) {
            $this->audit->log((int) $row['user_id'], $row['email'], $ip, 'invalid_token', false, 'expired');
            Util::sendError(401, 'invalid_token', 'Token expired — sign in again');
        }
        if ($row['status'] === 'banned') {
            $this->audit->log((int) $row['user_id'], $row['email'], $ip, 'invalid_token', false, 'banned');
            Util::sendError(403, 'account_banned', 'Account suspended');
        }

        // Touch last_used_at — best-effort; failure isn't fatal.
        $this->db->prepare('UPDATE auth_tokens SET last_used_at = ? WHERE token_hash = ?')
                 ->execute([time(), $tokenHash]);

        return [
            'user_id'    => (int) $row['user_id'],
            'email'      => $row['email'],
            'token_hash' => $tokenHash,
        ];
    }

    /**
     * Register a failed-login attempt. Returns true if the account is
     * NOW locked (caller may want to log a different event). Does the
     * write inside a transaction so the count + lock update are atomic.
     *
     * The caller doesn't check passwords while a lock runs, so failures
     * then are never counted and can't stretch it. Locking starts the
     * count again from zero: after the lock ends it takes another full
     * run of wrong passwords to lock again, not one.
     */
    public function recordFailedLogin(int $userId): bool
    {
        $threshold = (int) ($this->config['limits']['login_fail_threshold'] ?? 5);
        $lockSecs  = (int) ($this->config['limits']['lock_duration_seconds'] ?? 900);

        $this->db->beginTransaction();
        // `FOR UPDATE` so two failed attempts arriving in parallel still
        // produce a coherent count.
        $stmt = $this->db->prepare(
            'SELECT failed_login_count FROM users WHERE id = ? FOR UPDATE'
        );
        $stmt->execute([$userId]);
        $row = $stmt->fetch();
        if (!$row) {
            $this->db->rollBack();
            return false;
        }
        $newCount = ((int) $row['failed_login_count']) + 1;
        $lockedUntil = null;
        $isLocked = false;
        if ($newCount >= $threshold) {
            $lockedUntil = time() + $lockSecs;
            $isLocked = true;
            $newCount = 0;
        }
        $this->db->prepare(
            'UPDATE users SET failed_login_count = ?, locked_until = ? WHERE id = ?'
        )->execute([$newCount, $lockedUntil, $userId]);
        $this->db->commit();
        return $isLocked;
    }

    /**
     * Whether `$given` is the account's password, for an action that takes
     * more than a token (replacing the sharing key, deleting the account):
     * whoever holds a stolen token must not be able to do those.
     *
     * The same work on every path, so a missing or empty password, a locked
     * account and a wrong password answer alike (a locked account is refused
     * even with the right password: an answer that changed for it would tell a
     * guesser they had it). A wrong password counts as a failed login, with the
     * same lockout; while an account is locked the count doesn't move.
     */
    public function confirmPassword(int $userId, string $given): bool
    {
        $st = $this->db->prepare('SELECT password_hash, locked_until FROM users WHERE id = ?');
        $st->execute([$userId]);
        $row    = $st->fetch();
        $hash   = ($row && is_string($row['password_hash']) && $row['password_hash'] !== '')
            ? $row['password_hash'] : self::DUMMY_PASSWORD_HASH;
        $locked = $row && $row['locked_until'] !== null && (int) $row['locked_until'] > time();
        $good   = strlen($given) > 0 && strlen($given) <= 1024 && password_verify($given, $hash)
            && $hash !== self::DUMMY_PASSWORD_HASH && !$locked;
        if (!$good && $row && !$locked && $given !== '') {
            $this->recordFailedLogin($userId);
        }
        return $good;
    }

    /**
     * Resolve the raw token from the incoming request. Tries every place
     * a shared-host PHP-FPM setup might expose it, in priority order:
     *
     *   1. X-Auth-Token (custom)  — primary channel. Plain token, no prefix.
     *      Custom X-* headers are not touched by CF/Apache/PHP-FPM auth
     *      handling, so this is the reliable path on cPanel.
     *   2. Authorization: Bearer  — standard form. Includes the various
     *      $_SERVER fallbacks (HTTP_AUTHORIZATION, REDIRECT_HTTP_...,
     *      getallheaders()) for hosts that DO let it through.
     *
     * Returns '' when nothing is found.
     */
    private function readAuthToken(): string
    {
        // 1. Custom X-Auth-Token header (preferred).
        $xtok = $this->readHeader('X-Auth-Token', 'HTTP_X_AUTH_TOKEN');
        if ($xtok !== '') {
            return trim($xtok);
        }

        // 2. Authorization: Bearer <token>  (compat fallback).
        $auth = '';
        if (!empty($_SERVER['HTTP_AUTHORIZATION'])) {
            $auth = (string) $_SERVER['HTTP_AUTHORIZATION'];
        } elseif (!empty($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) {
            $auth = (string) $_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
        } else {
            foreach (['getallheaders', 'apache_request_headers'] as $fn) {
                if (function_exists($fn)) {
                    $headers = @$fn();
                    if (is_array($headers)) {
                        foreach ($headers as $k => $v) {
                            if (strcasecmp((string) $k, 'Authorization') === 0) {
                                $auth = (string) $v;
                                break 2;
                            }
                        }
                    }
                }
            }
        }
        if ($auth !== '' && stripos($auth, 'Bearer ') === 0) {
            return trim(substr($auth, 7));
        }
        return '';
    }

    /**
     * Read an arbitrary HTTP header by its public name plus the matching
     * $_SERVER key, walking the same fallbacks readAuthToken uses. Empty
     * string means absent.
     */
    private function readHeader(string $name, string $serverKey): string
    {
        if (!empty($_SERVER[$serverKey])) {
            return (string) $_SERVER[$serverKey];
        }
        $redirectKey = 'REDIRECT_' . $serverKey;
        if (!empty($_SERVER[$redirectKey])) {
            return (string) $_SERVER[$redirectKey];
        }
        foreach (['getallheaders', 'apache_request_headers'] as $fn) {
            if (function_exists($fn)) {
                $headers = @$fn();
                if (is_array($headers)) {
                    foreach ($headers as $k => $v) {
                        if (strcasecmp((string) $k, $name) === 0) {
                            return (string) $v;
                        }
                    }
                }
            }
        }
        return '';
    }

    /** Reset the failed-login counter on a clean login. */
    public function clearFailedLogins(int $userId, string $ip): void
    {
        $this->db->prepare(
            'UPDATE users SET failed_login_count = 0, locked_until = NULL,
                              last_login_at = ?, last_login_ip = ?
              WHERE id = ?'
        )->execute([time(), $ip, $userId]);
    }
}
