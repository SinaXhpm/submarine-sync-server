<?php
// Submarine sync server — the API. public/index.php runs this for every request.
//
// Routes (the Submarine app calls these; the paths may carry the server's
// base path and an optional /api in front):
//   POST /auth/signup, GET|POST /auth/verify, POST /auth/set-password,
//   POST /auth/login, /auth/logout, /auth/delete-account,
//   POST /auth/request-reset, /auth/reset-with-token,
//   POST /auth/request-login, /auth/login-with-link,
//   GET  /sync/profiles, POST /sync, POST /sync/delete,
//   /keys/* and /shares/* (src/sharing.php), GET /health.
//
// Error shape: { "error": "<code>", "message": "<words>", ...extras }

declare(strict_types=1);

use Submarine\Lib\Account;
use Submarine\Lib\Auth;
use Submarine\Lib\Bootstrap;
use Submarine\Lib\Util;

if (!defined('SUBMARINE_API')) {
    http_response_code(404);
    exit;
}

require __DIR__ . '/lib/Bootstrap.php';

$ctx    = Bootstrap::web(dirname(__DIR__));
$config = $ctx['config'];
$db     = $ctx['db'];
$rl     = $ctx['rl'];
$audit  = $ctx['audit'];
$auth   = $ctx['auth'];
$mailer = $ctx['mailer'];
$ip     = $ctx['ip'];
// What the per-IP limits count against: the address, or its /64 for IPv6.
$rlIp   = Util::rateKeyIp($ip);

// How old a request is when the answers that mustn't tell a registered email
// from an unknown one go out (Util::holdUntil). A failed sign-in runs one
// bcrypt check (a few hundred ms at cost 12 on a server CPU; `php bin/admin.php
// check` measures it here); the "check your inbox" answers do a few queries.
define('LOGIN_FAIL_FLOOR_MS', (int) $config['limits']['login_fail_floor_ms']);
define('ACCOUNT_MAIL_FLOOR_MS', (int) $config['limits']['account_mail_floor_ms']);

$pepper = (string) $config['security']['token_pepper'];

/**
 * Send one of the account emails, after the answer has gone out. Mail is
 * capped for the whole server (mail.per_hour), so a flood of requests for many
 * addresses can't turn it into a mail cannon.
 */
$sendAccountMail = static function (string $kind, int $userId, string $email, callable $send)
    use ($rl, $audit, $config, $ip): void {
    if ($rl->hit('mail:all', 3600) > (int) $config['mail']['per_hour']) {
        $audit->log($userId, $email, $ip, 'mail_suppressed', false, $kind);
        return;
    }
    $send();
};

/**
 * Mark a one-time code used, if nothing has yet. Run inside the transaction
 * that acts on it: only the request whose UPDATE flips used_at goes on, so two
 * requests racing with the same code can't both use it.
 */
$consumeToken = static function (string $tokenHash, string $purpose) use ($db): bool {
    $now = time();
    $st  = $db->prepare(
        'UPDATE verify_tokens SET used_at = ?
          WHERE token_hash = ? AND purpose = ? AND used_at IS NULL AND expires_at >= ?'
    );
    $st->execute([$now, $tokenHash, $purpose, $now]);
    return $st->rowCount() === 1;
};

/**
 * Before a new reset or sign-in code goes out, drop that account's older
 * codes of the same kind except the newest two. Three stay valid at once, so
 * a stranger asking for codes for someone else's address doesn't cancel the
 * one its owner is about to use; each is still single-use and expires.
 */
$pruneTokens = static function (int $userId, string $purpose) use ($db): void {
    $db->prepare(
        'DELETE FROM verify_tokens
          WHERE user_id = ? AND purpose = ?
            AND token_hash NOT IN (
                SELECT token_hash FROM (
                    SELECT token_hash FROM verify_tokens
                     WHERE user_id = ? AND purpose = ? AND used_at IS NULL AND expires_at >= ?
                     ORDER BY expires_at DESC
                     LIMIT 2
                ) AS keep_newest
            )'
    )->execute([$userId, $purpose, $userId, $purpose, time()]);
};

/**
 * The answer of the endpoints that must not tell whether an email has an
 * account (signup, request-reset, request-login): every branch leaves at the
 * same moment and with the same headers (sendJsonThenContinue adds
 * Content-Length and Connection: close where PHP can't end the request
 * itself), then does its slow work, if any, and stops.
 */
$sameAnswer = static function (array $answer, ?callable $after = null): never {
    Util::holdUntil(ACCOUNT_MAIL_FLOOR_MS);
    Util::sendJsonThenContinue(200, $answer);
    if ($after !== null) {
        $after();
    }
    exit;
};

/** A new sign-in token for the account; the raw value goes to the client once. */
$issueToken = static function (int $userId) use ($db, $pepper, $ip, $config): string {
    $token = Util::randomToken(32);
    $db->prepare(
        'INSERT INTO auth_tokens (token_hash, user_id, ip_address, expires_at, created_at) VALUES (?, ?, ?, ?, ?)'
    )->execute([Util::hashToken($token, $pepper), $userId, $ip, time() + (int) $config['token_ttl_seconds'], time()]);
    return $token;
};

// ---------------------------------------------------------------------------
// Every address gets a request budget, whatever the endpoint.
// ---------------------------------------------------------------------------
[$globalMax, $globalWindow] = $config['limits']['rate_ip_global'];
$globalCount = $rl->hit("global:ip:$rlIp", $globalWindow);
if ($globalCount > $globalMax) {
    // Logged once per address and window, not once per refused request: a
    // flood would otherwise write a row for every one of them.
    if ($globalCount === $globalMax + 1) {
        $audit->log(null, null, $ip, 'rate_limited', false, 'global');
    }
    header('Retry-After: ' . (string) $globalWindow);
    Util::sendError(429, 'rate_limited', 'Slow down (too many requests from this address)');
}

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------
$method = (string) ($_SERVER['REQUEST_METHOD'] ?? 'GET');
$path   = (string) (parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH) ?: '/');
$base   = (string) $config['base_path'];
if ($base !== '') {
    if ($path === $base) {
        $path = '/';
    } elseif (str_starts_with($path, $base . '/')) {
        $path = substr($path, strlen($base));
    } else {
        Util::sendError(404, 'no_route', 'Not found');
    }
}
$route = $path;
// An optional /api in front, as on Submarine's own server.
$path = preg_replace('#^/api(?=/|$)#', '', $path) ?: '/';

try {
    // -----------------------------------------------------------------------
    // The admin panel, when it is switched on (admin.password_hash).
    // -----------------------------------------------------------------------
    $adminPath = (string) $config['admin']['path'];
    if ((string) $config['admin']['password_hash'] !== '' && rtrim($route, '/') === $adminPath) {
        require __DIR__ . '/admin-panel.php';
        exit;
    }

    // -----------------------------------------------------------------------
    // GET /health — for uptime checks and the app's "Test connection".
    // -----------------------------------------------------------------------
    if ($method === 'GET' && $path === '/health') {
        Util::sendJson(200, ['ok' => true, 'time' => time()]);
    }

    // -----------------------------------------------------------------------
    // POST /auth/signup  { email }
    // -----------------------------------------------------------------------
    if ($method === 'POST' && $path === '/auth/signup') {
        [$ipMax, $ipWindow] = $config['limits']['rate_ip_signup'];
        $rl->enforce("signup:ip:$rlIp", $ipMax, $ipWindow);

        if ($config['signup'] !== 'open') {
            Util::sendError(403, 'signup_closed',
                'This server takes new accounts by invitation. Ask its admin for a verify token, then choose "Have a verify token?".');
        }

        // A full server says so to everybody, before any address is looked
        // at: an answer that depended on the address would tell which ones
        // have an account.
        $max = (int) $config['max_accounts'];
        if ($max > 0 && (int) $db->query('SELECT COUNT(*) FROM users')->fetchColumn() >= $max) {
            Util::sendError(403, 'signup_full', 'This server takes no new accounts right now.');
        }

        $body  = Util::readJson($config['limits']['max_json_bytes']);
        $email = trim(strtolower(Util::str($body, 'email')));
        if (!Util::validEmail($email)) {
            $audit->log(null, $email !== '' ? mb_substr($email, 0, 191) : null, $ip, 'signup_blocked', false, 'invalid_email');
            Util::sendError(400, 'invalid_email', 'Provide a valid email');
        }

        // Per-email signup cap: stops "rotate IP, hit one email" loops.
        [$emMax, $emWindow] = $config['limits']['rate_email_signup'];
        $rl->enforce("signup:email:$email", $emMax, $emWindow);
        $answer = ['status' => 'pending', 'message' => 'Check your inbox'];

        $db->beginTransaction();
        $stmt = $db->prepare('SELECT id, status FROM users WHERE email = ? FOR UPDATE');
        $stmt->execute([$email]);
        $existing = $stmt->fetch();

        // An active account's signup looks exactly like a new one from
        // outside (the same answer at the same moment, with the same
        // headers), so the endpoint can't be used to find out which addresses
        // have an account. The existing account gets no mail.
        if ($existing && $existing['status'] === 'active') {
            $db->rollBack();
            $audit->log((int) $existing['id'], $email, $ip, 'signup_blocked', false, 'already_active');
            $sameAnswer($answer);
        }

        if ($existing) {
            $userId = (int) $existing['id'];
        } else {
            $db->prepare('INSERT INTO users (email, status) VALUES (?, "pending")')->execute([$email]);
            $userId = (int) $db->lastInsertId();
        }
        // Only the newest sign-up code works. An admin's invitation code
        // (purpose "invite") is left alone, so a stranger signing up with an
        // invited address can't cancel it.
        $db->prepare('DELETE FROM verify_tokens WHERE user_id = ? AND purpose = "verify"')->execute([$userId]);
        $verifyToken = Util::randomToken(24);
        $db->prepare(
            'INSERT INTO verify_tokens (token_hash, user_id, purpose, expires_at) VALUES (?, ?, "verify", ?)'
        )->execute([Util::hashToken($verifyToken, $pepper), $userId, time() + (int) $config['limits']['verify_token_ttl']]);
        $db->commit();
        $audit->log($userId, $email, $ip, 'signup', true);

        // The answer goes out first, and the mail after it.
        $sameAnswer($answer, fn () => $sendAccountMail('verify', $userId, $email, fn () => $mailer->sendVerify($email, $verifyToken, $ip)));
    }

    // -----------------------------------------------------------------------
    // POST /auth/verify { token }  (GET /auth/verify?token=... for the apps)
    // -----------------------------------------------------------------------
    if (($method === 'GET' || $method === 'POST') && $path === '/auth/verify') {
        [$ipMax, $ipWindow] = $config['limits']['rate_ip_verify'];
        $rl->enforce("verify:ip:$rlIp", $ipMax, $ipWindow);

        $token = $method === 'POST'
            ? Util::str(Util::readJson($config['limits']['max_json_bytes']), 'token')
            : (is_string($_GET['token'] ?? null) ? $_GET['token'] : '');
        $token = trim($token);
        if ($token === '' || strlen($token) > 128) {
            Util::sendError(400, 'missing_token', 'Verification token required');
        }

        // A sign-up code (verify) or an admin's invitation code (invite).
        $tokenHash = Util::hashToken($token, $pepper);
        $stmt = $db->prepare(
            'SELECT v.user_id, v.purpose, v.expires_at, v.used_at, u.email, u.status
               FROM verify_tokens v JOIN users u ON u.id = v.user_id
              WHERE v.token_hash = ? AND v.purpose IN ("verify", "invite")'
        );
        $stmt->execute([$tokenHash]);
        $row = $stmt->fetch();
        // One answer for every failure (unknown, used, expired, an account
        // that already has its password).
        if (!$row || $row['used_at'] || (int) $row['expires_at'] < time() || $row['status'] === 'active') {
            $reason = !$row ? 'unknown' : ($row['used_at'] ? 'used' : ($row['status'] === 'active' ? 'already_active' : 'expired'));
            $audit->log($row ? (int) $row['user_id'] : null, $row['email'] ?? null, $ip, 'verify_failed', false, $reason);
            Util::sendError(400, 'verify_failed', 'Invalid or expired verification code');
        }
        if ($row['status'] === 'banned') {
            Util::sendError(403, 'account_banned', 'Account suspended');
        }

        $db->beginTransaction();
        if (!$consumeToken($tokenHash, (string) $row['purpose'])) {
            $db->rollBack();
            $audit->log((int) $row['user_id'], $row['email'], $ip, 'verify_failed', false, 'used');
            Util::sendError(400, 'verify_failed', 'Invalid or expired verification code');
        }
        $claimToken = Util::randomToken(24);
        $db->prepare(
            'INSERT INTO verify_tokens (token_hash, user_id, purpose, expires_at) VALUES (?, ?, "claim", ?)'
        )->execute([Util::hashToken($claimToken, $pepper), $row['user_id'], time() + (int) $config['limits']['claim_token_ttl']]);
        $db->commit();
        $audit->log((int) $row['user_id'], $row['email'], $ip, 'verify', true);
        Util::sendJson(200, ['claim_token' => $claimToken, 'email' => $row['email']]);
    }

    // -----------------------------------------------------------------------
    // POST /auth/set-password { claim_token, password }
    // -----------------------------------------------------------------------
    if ($method === 'POST' && $path === '/auth/set-password') {
        $body     = Util::readJson($config['limits']['max_json_bytes']);
        $claim    = trim(Util::str($body, 'claim_token'));
        $password = Util::str($body, 'password');
        $pwMin    = (int) $config['limits']['password_min_length'];
        if ($claim === '' || strlen($claim) > 128) {
            Util::sendError(400, 'invalid_input', "claim_token + password (>= $pwMin chars) required");
        }
        $bad = Util::passwordProblem($password, $pwMin);
        if ($bad !== null) {
            Util::sendError(400, 'invalid_input', $bad);
        }

        $claimHash = Util::hashToken($claim, $pepper);
        $stmt = $db->prepare(
            'SELECT v.user_id, v.expires_at, v.used_at, u.email, u.status
               FROM verify_tokens v JOIN users u ON u.id = v.user_id
              WHERE v.token_hash = ? AND v.purpose = "claim"'
        );
        $stmt->execute([$claimHash]);
        $row = $stmt->fetch();
        // Choosing the first password is for an account that doesn't have one
        // yet. A claim that outlived that (the account became active another
        // way) is refused like an unknown one; a new password for an active
        // account goes through reset-with-token, which also signs out.
        if (!$row || $row['used_at'] || (int) $row['expires_at'] < time() || $row['status'] === 'active') {
            $reason = !$row ? 'unknown_claim' : ($row['used_at'] ? 'used' : ($row['status'] === 'active' ? 'already_active' : 'expired'));
            $audit->log($row ? (int) $row['user_id'] : null, $row['email'] ?? null, $ip, 'set_password_failed', false, $reason);
            Util::sendError(400, 'invalid_claim', 'Invalid or expired claim token');
        }
        if ($row['status'] === 'banned') {
            Util::sendError(403, 'account_banned', 'Account suspended');
        }

        $hash = password_hash($password, PASSWORD_DEFAULT);
        $db->beginTransaction();
        if (!$consumeToken($claimHash, 'claim')) {
            $db->rollBack();
            $audit->log((int) $row['user_id'], $row['email'], $ip, 'set_password_failed', false, 'used');
            Util::sendError(400, 'invalid_claim', 'Invalid or expired claim token');
        }
        $upd = $db->prepare('UPDATE users SET password_hash = ?, status = "active", failed_login_count = 0, locked_until = NULL
                              WHERE id = ? AND status = "pending"');
        $upd->execute([$hash, $row['user_id']]);
        if ($upd->rowCount() !== 1) {
            $db->rollBack();
            Util::sendError(400, 'invalid_claim', 'Invalid or expired claim token');
        }
        // The other sign-up, invitation and claim codes have done their job.
        $db->prepare('DELETE FROM verify_tokens WHERE user_id = ? AND purpose IN ("verify", "invite", "claim") AND token_hash <> ?')
           ->execute([$row['user_id'], $claimHash]);
        $authToken = $issueToken((int) $row['user_id']);
        $db->commit();
        $audit->log((int) $row['user_id'], $row['email'], $ip, 'set_password', true);
        Util::sendJson(200, ['token' => $authToken, 'email' => $row['email']]);
    }

    // -----------------------------------------------------------------------
    // POST /auth/login { email, password }
    // -----------------------------------------------------------------------
    if ($method === 'POST' && $path === '/auth/login') {
        [$ipMax, $ipWindow] = $config['limits']['rate_ip_login'];
        $rl->enforce("login:ip:$rlIp", $ipMax, $ipWindow);

        $body     = Util::readJson($config['limits']['max_json_bytes']);
        $email    = trim(strtolower(Util::str($body, 'email')));
        $password = Util::str($body, 'password');
        if (!Util::validEmail($email) || $password === '' || strlen($password) > 1024) {
            Util::constantTimeJitter();
            Util::sendError(400, 'invalid_input', 'email + password required');
        }

        // Per-email attempt cap (one email tried from many addresses).
        [$emMax, $emWindow] = $config['limits']['rate_email_login_attempt'];
        $rl->enforce("login:email:$email", $emMax, $emWindow);

        $stmt = $db->prepare('SELECT id, password_hash, status, locked_until FROM users WHERE email = ?');
        $stmt->execute([$email]);
        $row = $stmt->fetch();

        // One bcrypt check of the same cost on every path, so the time a
        // failure takes doesn't tell a missing account, one without a password
        // yet, a locked one and a wrong password apart. A locked account's
        // password isn't checked at all: an answer that changed for the right
        // password would tell a guesser they had it.
        $usable = $row && $row['password_hash'] && $row['status'] === 'active';
        $locked = $usable && $row['locked_until'] !== null && (int) $row['locked_until'] > time();
        if ($usable && !$locked && !str_contains($password, "\0")) {
            $okPwd = password_verify($password, (string) $row['password_hash']);
        } else {
            password_verify(str_replace("\0", '', $password), Auth::DUMMY_PASSWORD_HASH);
            $okPwd = false;
        }

        if (!$okPwd) {
            // Only a real, active account whose password was checked moves
            // toward the lock: nobody can lock a pending account by guessing.
            if ($usable && !$locked) {
                $nowLocked = $auth->recordFailedLogin((int) $row['id']);
                $audit->log((int) $row['id'], $email, $ip, 'login_failure', false, $nowLocked ? 'now_locked' : 'bad_password');
            } else {
                $audit->log($row ? (int) $row['id'] : null, $email, $ip, 'login_failure', false,
                            !$row ? 'no_such_user' : ($locked ? 'locked' : 'inactive_account'));
            }
            Util::holdUntil(LOGIN_FAIL_FLOOR_MS);
            $mins = intdiv((int) $config['limits']['lock_duration_seconds'], 60);
            $byMail = $mailer->enabled() ? ' signing in by email still works.' : ' the server\'s admin can make you a reset code.';
            Util::sendError(401, 'invalid_credentials',
                "Wrong email or password. After several wrong tries, password sign-in pauses for $mins minutes;" . $byMail);
        }

        // A hash made at a lower cost is redone at today's, while the password is at hand.
        if (password_needs_rehash((string) $row['password_hash'], PASSWORD_DEFAULT)) {
            $db->prepare('UPDATE users SET password_hash = ? WHERE id = ?')
               ->execute([password_hash($password, PASSWORD_DEFAULT), (int) $row['id']]);
        }
        $authToken = $issueToken((int) $row['id']);
        $auth->clearFailedLogins((int) $row['id'], $ip);
        $audit->log((int) $row['id'], $email, $ip, 'login_success', true);
        Util::sendJson(200, ['token' => $authToken, 'email' => $email]);
    }

    // -----------------------------------------------------------------------
    // POST /auth/logout  [auth]
    // -----------------------------------------------------------------------
    if ($method === 'POST' && $path === '/auth/logout') {
        $c = $auth->requireAuth($ip);
        $db->prepare('DELETE FROM auth_tokens WHERE token_hash = ?')->execute([$c['token_hash']]);
        $audit->log($c['user_id'], $c['email'], $ip, 'logout', true);
        Util::sendJson(200, ['ok' => true]);
    }

    // -----------------------------------------------------------------------
    // POST /auth/delete-account { password }  [auth]
    // -----------------------------------------------------------------------
    // The token alone isn't enough: whoever holds a stolen token must not be
    // able to delete the account. A wrong password counts as a failed login.
    if ($method === 'POST' && $path === '/auth/delete-account') {
        $c = $auth->requireAuth($ip);
        $rl->enforce("delete-account:user:{$c['user_id']}", 5, 3600);
        $rl->enforce("delete-account:ip:$rlIp", 20, 3600);
        $body  = Util::readJson(4096);
        $given = Util::str($body, 'password');
        if (!$auth->confirmPassword((int) $c['user_id'], $given)) {
            $audit->log($c['user_id'], $c['email'], $ip, 'account_delete_denied', false, $given === '' ? 'no_password' : 'bad_password');
            Util::sendError(403, 'reauth_required', 'Deleting your account needs your account password (password).');
        }
        Account::delete($db, (int) $c['user_id']);
        // Logged without the address: the account is gone.
        $audit->log(null, null, $ip, 'account_deleted', true, 'uid=' . $c['user_id']);
        Util::sendJson(200, ['ok' => true]);
    }

    // -----------------------------------------------------------------------
    // POST /auth/request-reset { email }
    // -----------------------------------------------------------------------
    // The same answer whether or not the address has an account.
    if ($method === 'POST' && $path === '/auth/request-reset') {
        [$ipMax, $ipWindow] = $config['limits']['rate_ip_request_reset'];
        $rl->enforce("reset:ip:$rlIp", $ipMax, $ipWindow);
        $answer = ['status' => 'ok', 'message' => 'If that email is registered, a reset code is on its way'];

        $body  = Util::readJson($config['limits']['max_json_bytes']);
        $email = trim(strtolower(Util::str($body, 'email')));
        if (!Util::validEmail($email)) {
            $sameAnswer($answer);
        }
        [$emMax, $emWindow] = $config['limits']['rate_email_request_reset'];
        $rl->enforce("reset:email:$email", $emMax, $emWindow);

        $stmt = $db->prepare('SELECT id, status FROM users WHERE email = ?');
        $stmt->execute([$email]);
        $row = $stmt->fetch();
        if (!$row || $row['status'] !== 'active' || !$mailer->enabled()) {
            $audit->log($row ? (int) $row['id'] : null, $email, $ip, 'request_reset_blocked', false,
                        !$row ? 'no_such_user' : ($row['status'] !== 'active' ? "status:{$row['status']}" : 'mail_off'));
            $sameAnswer($answer);
        }
        $userId = (int) $row['id'];
        $pruneTokens($userId, 'reset');
        $token = Util::randomToken(24);
        $db->prepare('INSERT INTO verify_tokens (token_hash, user_id, purpose, expires_at) VALUES (?, ?, "reset", ?)')
           ->execute([Util::hashToken($token, $pepper), $userId, time() + (int) $config['limits']['reset_token_ttl']]);
        $audit->log($userId, $email, $ip, 'request_reset', true);
        $sameAnswer($answer, fn () => $sendAccountMail('reset', $userId, $email, fn () => $mailer->sendReset($email, $token, $ip)));
    }

    // -----------------------------------------------------------------------
    // POST /auth/reset-with-token { reset_token, password }
    // -----------------------------------------------------------------------
    // A new password ends every sign-in of the account and the lock.
    if ($method === 'POST' && $path === '/auth/reset-with-token') {
        $body     = Util::readJson($config['limits']['max_json_bytes']);
        $token    = trim(Util::str($body, 'reset_token'));
        $password = Util::str($body, 'password');
        $pwMin    = (int) $config['limits']['password_min_length'];
        if ($token === '' || strlen($token) > 128) {
            Util::sendError(400, 'invalid_input', "reset_token + password (>= $pwMin chars) required");
        }
        $bad = Util::passwordProblem($password, $pwMin);
        if ($bad !== null) {
            Util::sendError(400, 'invalid_input', $bad);
        }

        $tokenHash = Util::hashToken($token, $pepper);
        $stmt = $db->prepare(
            'SELECT v.user_id, v.expires_at, v.used_at, u.email, u.status
               FROM verify_tokens v JOIN users u ON u.id = v.user_id
              WHERE v.token_hash = ? AND v.purpose = "reset"'
        );
        $stmt->execute([$tokenHash]);
        $row = $stmt->fetch();
        if (!$row || $row['used_at'] || (int) $row['expires_at'] < time()) {
            $reason = !$row ? 'unknown' : ($row['used_at'] ? 'used' : 'expired');
            $audit->log($row ? (int) $row['user_id'] : null, $row['email'] ?? null, $ip, 'reset_failed', false, $reason);
            Util::sendError(400, 'reset_failed', 'Invalid or expired reset code');
        }
        if ($row['status'] === 'banned') {
            Util::sendError(403, 'account_banned', 'Account suspended');
        }
        if ($row['status'] !== 'active') {
            $audit->log((int) $row['user_id'], $row['email'], $ip, 'reset_failed', false, 'inactive');
            Util::sendError(400, 'reset_failed', 'Invalid or expired reset code');
        }

        $hash = password_hash($password, PASSWORD_DEFAULT);
        $db->beginTransaction();
        if (!$consumeToken($tokenHash, 'reset')) {
            $db->rollBack();
            $audit->log((int) $row['user_id'], $row['email'], $ip, 'reset_failed', false, 'used');
            Util::sendError(400, 'reset_failed', 'Invalid or expired reset code');
        }
        $uid = (int) $row['user_id'];
        $db->prepare('UPDATE users SET password_hash = ?, failed_login_count = 0, locked_until = NULL WHERE id = ?')->execute([$hash, $uid]);
        $db->prepare('DELETE FROM verify_tokens WHERE user_id = ? AND purpose = "reset" AND token_hash <> ?')->execute([$uid, $tokenHash]);
        $db->prepare('DELETE FROM auth_tokens WHERE user_id = ?')->execute([$uid]);
        $authToken = $issueToken($uid);
        $db->commit();
        $audit->log($uid, $row['email'], $ip, 'reset_password', true);
        Util::sendJson(200, ['token' => $authToken, 'email' => $row['email']]);
    }

    // -----------------------------------------------------------------------
    // POST /auth/request-login { email } — a sign-in code by mail.
    // -----------------------------------------------------------------------
    // It works while password sign-in is locked: that lock is about guessing
    // a password, which this doesn't involve.
    if ($method === 'POST' && $path === '/auth/request-login') {
        [$ipMax, $ipWindow] = $config['limits']['rate_ip_request_login'];
        $rl->enforce("loginlink:ip:$rlIp", $ipMax, $ipWindow);
        $answer = ['status' => 'ok', 'message' => 'If that email is registered, a sign-in code is on its way'];

        $body  = Util::readJson($config['limits']['max_json_bytes']);
        $email = trim(strtolower(Util::str($body, 'email')));
        if (!Util::validEmail($email)) {
            $sameAnswer($answer);
        }
        [$emMax, $emWindow] = $config['limits']['rate_email_request_login'];
        $rl->enforce("loginlink:email:$email", $emMax, $emWindow);

        $stmt = $db->prepare('SELECT id, status FROM users WHERE email = ?');
        $stmt->execute([$email]);
        $row = $stmt->fetch();
        if (!$row || $row['status'] !== 'active' || !$mailer->enabled()) {
            $audit->log($row ? (int) $row['id'] : null, $email, $ip, 'request_login_blocked', false,
                        !$row ? 'no_such_user' : ($row['status'] !== 'active' ? "status:{$row['status']}" : 'mail_off'));
            $sameAnswer($answer);
        }
        $userId = (int) $row['id'];
        $pruneTokens($userId, 'login');
        $token = Util::randomToken(24);
        $db->prepare('INSERT INTO verify_tokens (token_hash, user_id, purpose, expires_at) VALUES (?, ?, "login", ?)')
           ->execute([Util::hashToken($token, $pepper), $userId, time() + (int) $config['limits']['login_token_ttl']]);
        $audit->log($userId, $email, $ip, 'request_login_link', true);
        $sameAnswer($answer, fn () => $sendAccountMail('login_link', $userId, $email, fn () => $mailer->sendLoginLink($email, $token, $ip)));
    }

    // -----------------------------------------------------------------------
    // POST /auth/login-with-link { login_token }
    // -----------------------------------------------------------------------
    // Single use. The mailbox proves who it is, so it also ends a lock.
    if ($method === 'POST' && $path === '/auth/login-with-link') {
        $body  = Util::readJson($config['limits']['max_json_bytes']);
        $token = trim(Util::str($body, 'login_token'));
        if ($token === '' || strlen($token) > 128) {
            Util::sendError(400, 'invalid_input', 'login_token required');
        }
        $tokenHash = Util::hashToken($token, $pepper);
        $stmt = $db->prepare(
            'SELECT v.user_id, v.expires_at, v.used_at, u.email, u.status
               FROM verify_tokens v JOIN users u ON u.id = v.user_id
              WHERE v.token_hash = ? AND v.purpose = "login"'
        );
        $stmt->execute([$tokenHash]);
        $row = $stmt->fetch();
        if (!$row || $row['used_at'] || (int) $row['expires_at'] < time()) {
            $reason = !$row ? 'unknown' : ($row['used_at'] ? 'used' : 'expired');
            $audit->log($row ? (int) $row['user_id'] : null, $row['email'] ?? null, $ip, 'login_link_failed', false, $reason);
            Util::sendError(400, 'login_failed', 'Invalid or expired sign-in code');
        }
        if ($row['status'] === 'banned') {
            Util::sendError(403, 'account_banned', 'Account suspended');
        }
        if ($row['status'] !== 'active') {
            $audit->log((int) $row['user_id'], $row['email'], $ip, 'login_link_failed', false, 'inactive');
            Util::sendError(400, 'login_failed', 'Invalid or expired sign-in code');
        }
        $db->beginTransaction();
        if (!$consumeToken($tokenHash, 'login')) {
            $db->rollBack();
            $audit->log((int) $row['user_id'], $row['email'], $ip, 'login_link_failed', false, 'used');
            Util::sendError(400, 'login_failed', 'Invalid or expired sign-in code');
        }
        $authToken = $issueToken((int) $row['user_id']);
        $db->commit();
        $auth->clearFailedLogins((int) $row['user_id'], $ip);
        $audit->log((int) $row['user_id'], $row['email'], $ip, 'login_link', true);
        Util::sendJson(200, ['token' => $authToken, 'email' => $row['email']]);
    }

    // -----------------------------------------------------------------------
    // GET /sync/profiles  [auth] — the caller's cloud profiles, for the
    // picker on a new device. Names and counts only, never a record's contents.
    // -----------------------------------------------------------------------
    if ($method === 'GET' && $path === '/sync/profiles') {
        $c = $auth->requireAuth($ip);
        [$uMax, $uWindow] = $config['limits']['rate_user_global'];
        $rl->enforce("user:{$c['user_id']}:global", $uMax, $uWindow);

        $stmt = $db->prepare(
            "SELECT r.profile                                            AS profile,
                    COALESCE(p.name, r.profile)                          AS name,
                    COUNT(*)                                             AS records,
                    SUM(r.deleted = 0 AND r.entity_type <> 'dek_escrow') AS live_records,
                    MAX(r.updated_at)                                    AS last_updated
               FROM sync_records r
               LEFT JOIN sync_profiles p ON p.user_id = r.user_id AND p.profile = r.profile
              WHERE r.user_id = ?
              GROUP BY r.profile, p.name
              ORDER BY name"
        );
        $stmt->execute([$c['user_id']]);
        $out = array_map(static fn ($r) => [
            'profile'      => (string) $r['profile'],
            'name'         => (string) $r['name'],
            'records'      => (int) $r['records'],
            'live_records' => (int) $r['live_records'],
            'last_updated' => (string) $r['last_updated'],
        ], $stmt->fetchAll());
        $audit->log($c['user_id'], $c['email'], $ip, 'sync_profiles', true, 'count=' . count($out));
        Util::sendJson(200, ['profiles' => $out]);
    }

    // -----------------------------------------------------------------------
    // POST /sync/delete { profile }  [auth] — remove one of the caller's own
    // profiles from the server (records, name, revision counter).
    // -----------------------------------------------------------------------
    if ($method === 'POST' && $path === '/sync/delete') {
        $c = $auth->requireAuth($ip);
        [$uMax, $uWindow] = $config['limits']['rate_user_global'];
        $rl->enforce("user:{$c['user_id']}:global", $uMax, $uWindow);

        $body    = Util::readJson($config['limits']['max_json_bytes']);
        $profile = Util::str($body, 'profile');
        if ($profile === '' || !preg_match('/^[A-Za-z0-9_\-]{1,32}\z/', $profile)) {
            Util::sendError(400, 'bad_request', 'profile required');
        }
        $partition = ['user_id' => $c['user_id'], 'profile' => $profile];
        $db->beginTransaction();
        \Submarine\Lib\SyncDelta::lockForDelete($db, 'sync_revs', $partition);
        $stmt = $db->prepare('DELETE FROM sync_records WHERE user_id = ? AND profile = ?');
        $stmt->execute([$c['user_id'], $profile]);
        $deleted = $stmt->rowCount();
        $db->prepare('DELETE FROM sync_profiles WHERE user_id = ? AND profile = ?')->execute([$c['user_id'], $profile]);
        \Submarine\Lib\SyncDelta::forget($db, 'sync_revs', $partition);
        $db->commit();
        $audit->log($c['user_id'], $c['email'], $ip, 'sync_delete', true, "profile=$profile deleted=$deleted");
        Util::sendJson(200, ['deleted' => (int) $deleted]);
    }

    // -----------------------------------------------------------------------
    // POST /sync  [auth] — the profile's records, both ways (src/sync.php).
    // -----------------------------------------------------------------------
    if ($method === 'POST' && $path === '/sync') {
        require __DIR__ . '/sync.php';
    }

    // -----------------------------------------------------------------------
    // /keys/* and /shares/*  [auth] — sharing a profile (src/sharing.php).
    // -----------------------------------------------------------------------
    if (str_starts_with($path, '/keys/') || str_starts_with($path, '/shares/')) {
        require __DIR__ . '/sharing.php';
    }

    Util::sendError(404, 'no_route', 'Not found');
} catch (Throwable $e) {
    if ($db->inTransaction()) {
        $db->rollBack();
    }
    // The details go to the server log only.
    error_log('[submarine] ' . get_class($e) . ': ' . $e->getMessage() . ' @ ' . basename($e->getFile()) . ':' . $e->getLine());
    Util::sendError(500, 'internal', 'Internal server error');
}
