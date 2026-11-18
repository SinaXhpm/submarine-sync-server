<?php
// Submarine sync server — the web admin panel (optional).
//
// On only when admin.password_hash is set (SUBMARINE_ADMIN_PASSWORD_HASH), at
// admin.path (SUBMARINE_ADMIN_PATH, /admin by default). Everything it does can
// also be done with bin/admin.php.
//
// What it shows: account emails, status, dates, how many profiles and bytes
// each account holds, and totals. Never a record's contents: they are
// encrypted on the devices, and the keys never reach the server.
//
// Security:
//   - HTTPS only (directly, or from a trusted proxy that says so). Plain http
//     from a browser on this machine only when admin.allow_http_local is on,
//     and never for a request that came through a proxy.
//   - The password is checked with password_verify. Sign-in tries are counted
//     before the check: past 5 per address in 15 minutes, or 50 in an hour in
//     all, the password isn't checked at all for a while.
//   - A session is a random cookie (HttpOnly, SameSite=Strict; on HTTPS also
//     Secure, with the __Host- prefix, or __Secure- and the panel's path under
//     a base path); only an HMAC of it is stored. It ends after 30 idle
//     minutes, after 12 hours, or when the password hash changes.
//   - Every action is a POST with the session's CSRF token, compared in
//     constant time. Every action is written to the event log.
//   - No script at all; the Content-Security-Policy allows only this page's
//     own style, by nonce.
//
// Runs inside src/api.php's try{} with $config, $db, $rl, $audit, $ip, $rlIp and
// $method in scope.

use Submarine\Lib\Admin;
use Submarine\Lib\Util;

if (!defined('SUBMARINE_API')) {
    http_response_code(404);
    exit;
}

const ADMIN_IDLE_SECONDS    = 1800;
const ADMIN_SESSION_SECONDS = 43200;
const ADMIN_PAGE_SIZE       = 50;

$panel  = (string) $config['base_path'] . (string) $config['admin']['path'];
$pwHash = (string) $config['admin']['password_hash'];
$pepper = (string) $config['security']['token_pepper'];
$now    = time();
$https  = Util::isHttps($config);
$remote = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
// Plain http is allowed only when the operator switched it on, and only for a
// browser on this machine. Both must say so: the browser was given a loopback
// name (http://localhost..., also through an SSH tunnel), and the connection
// comes from this machine (loopback; in the Docker image, from the host,
// whose connections to the published port arrive from the container's
// gateway). The name alone can be made up by anyone who reaches the port; the
// address alone is also what a reverse proxy on this machine has. A request
// that carries any proxy header came through a proxy (nginx's proxy_pass,
// cloudflared, Apache's ProxyPass), so it never counts as local.
$proxied = false;
foreach (['HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED_PROTO', 'HTTP_X_FORWARDED_HOST', 'HTTP_FORWARDED', 'HTTP_X_REAL_IP',
          'HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_SERVER', 'HTTP_VIA'] as $h) {
    if (isset($_SERVER[$h])) $proxied = true;
}
$hostName = strtolower((string) preg_replace('/:\d+$/', '', (string) ($_SERVER['HTTP_HOST'] ?? '')));
$fromHere = in_array($remote, ['127.0.0.1', '::1'], true) || ($remote !== '' && $remote === Util::dockerGateway());
$local  = !empty($config['admin']['allow_http_local']) && !$proxied && $fromHere
    && in_array($hostName, ['localhost', '127.0.0.1', '[::1]'], true);
$nonce  = base64_encode(random_bytes(16));

header('Content-Type: text/html; charset=utf-8');
header("Content-Security-Policy: default-src 'none'; style-src 'nonce-$nonce'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('Cache-Control: no-store');
header('X-Robots-Tag: noindex, nofollow');
header_remove('X-Powered-By');
if ($https) {
    header('Strict-Transport-Security: max-age=63072000');
}

function h(?string $s): string
{
    return htmlspecialchars((string) $s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function admin_page(string $title, string $body, string $nonce): never
{
    $css = <<<'CSS'
:root{--bg:#f6f7f9;--card:#fff;--ink:#1b1f24;--muted:#5b6672;--line:#dde2e8;--accent:#0b6bcb;--bad:#b42318;--ok:#067647;color-scheme:light}
@media (prefers-color-scheme:dark){:root{--bg:#0f1318;--card:#171c22;--ink:#e6eaef;--muted:#9aa5b1;--line:#2a323c;--accent:#5aa9f5;--bad:#f97066;--ok:#47cd89;color-scheme:dark}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;padding:24px 16px}
main{max-width:1100px;margin:0 auto}h1{font-size:20px;margin:0 0 4px}h2{font-size:15px;margin:0 0 10px}
.muted{color:var(--muted)}.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin:0 0 16px}
.top{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:16px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}
.stat b{display:block;font-size:20px}.stat span{color:var(--muted);font-size:12px}
form.inline{display:inline}input,button{font:inherit}
input[type=text],input[type=email],input[type=password],input[type=search]{padding:7px 9px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--ink);min-width:0}
button{padding:7px 12px;border-radius:6px;border:1px solid var(--line);background:var(--card);color:var(--ink);cursor:pointer}
button.primary{background:var(--accent);border-color:var(--accent);color:#fff}button.danger{color:var(--bad)}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.wrap{overflow-x:auto}table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:8px 6px;border-top:1px solid var(--line);vertical-align:top;white-space:nowrap}
th{font-weight:600;color:var(--muted);font-size:12px;border-top:0}td.actions{white-space:normal;min-width:260px}td.actions form{margin:0 4px 4px 0}
.flash{padding:10px 12px;border-radius:8px;margin:0 0 16px;border:1px solid var(--line);background:var(--card)}.flash.err{border-color:var(--bad);color:var(--bad)}
.code{font:600 15px ui-monospace,Menlo,Consolas,monospace;padding:12px;border:1px dashed var(--line);border-radius:8px;user-select:all;word-break:break-all;background:var(--bg)}
.login{max-width:360px;margin:8vh auto}.login input{width:100%;margin:6px 0 12px}
.pill{font-size:12px;padding:1px 7px;border-radius:999px;border:1px solid var(--line)}.pill.banned{color:var(--bad)}.pill.active{color:var(--ok)}
.pager{display:flex;gap:12px;margin-top:10px}
CSS;
    echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
        . '<meta name="robots" content="noindex,nofollow"><title>' . h($title) . '</title><style nonce="' . h($nonce) . '">' . $css . '</style></head><body><main>'
        . $body . '</main></body></html>';
    exit;
}

function admin_redirect(string $to): never
{
    header('Location: ' . $to, true, 303);
    exit;
}

function bytes_text(int $b): string
{
    if ($b < 1024) return $b . ' B';
    if ($b < 1048576) return round($b / 1024, 1) . ' KB';
    return round($b / 1048576, 1) . ' MB';
}

function when_text(?int $ts, int $now): string
{
    if (!$ts) return '<span class="muted">-</span>';
    $s = $now - $ts;
    $t = $s < 120 ? 'just now' : ($s < 7200 ? intdiv($s, 60) . ' min ago' : ($s < 172800 ? intdiv($s, 3600) . ' h ago' : gmdate('Y-m-d', $ts)));
    return '<span title="' . gmdate('Y-m-d H:i', $ts) . ' UTC">' . h($t) . '</span>';
}

// ---------------------------------------------------------------------------
// HTTPS, or a browser on this machine.
// ---------------------------------------------------------------------------
if (!$https && !$local) {
    http_response_code(403);
    admin_page('Admin panel', '<div class="card login"><h1>HTTPS needed</h1><p>The admin panel only opens over HTTPS, so the '
        . 'password and the session can\'t be read on the way. Open it at its https:// address, or use the command line: '
        . '<code>php bin/admin.php</code>. (For a browser on the server itself, plain http can be switched on with '
        . 'SUBMARINE_ADMIN_ALLOW_HTTP_LOCAL.)</p></div>', $nonce);
}
if (!in_array($method, ['GET', 'HEAD', 'POST'], true)) {
    http_response_code(405);
    header('Allow: GET, POST');
    admin_page('Admin panel', '<p>Method not allowed.</p>', $nonce);
}

// ---------------------------------------------------------------------------
// The session.
// ---------------------------------------------------------------------------
// At the root, __Host- (Secure, Path=/, no Domain). Under a base path the
// cookie is kept to the panel's own path, which __Host- doesn't allow, so it is
// __Secure- (Secure) with Path=<the panel>.
$atRoot = (string) $config['base_path'] === '';
$cookieName = !$https ? 'submarine_admin' : ($atRoot ? '__Host-submarine_admin' : '__Secure-submarine_admin');
$cookiePath = $https && $atRoot ? '/' : $panel;
$pwTag = substr(hash('sha256', $pwHash), 0, 16);
$setCookie = static function (string $value, int $expires) use ($cookieName, $cookiePath, $https): void {
    setcookie($cookieName, $value, [
        'expires'  => $expires,
        'path'     => $cookiePath,
        'secure'   => $https,
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
};
$session = null;
$raw = (string) ($_COOKIE[$cookieName] ?? '');
if (preg_match('/^[0-9a-f]{64}$/', $raw)) {
    $st = $db->prepare('SELECT token_hash, csrf, pw_tag, created_at, seen_at, flash FROM admin_sessions WHERE token_hash = ?');
    $st->execute([Util::hashToken($raw, $pepper)]);
    $row = $st->fetch();
    if ($row && hash_equals((string) $row['pw_tag'], $pwTag)
        && $now - (int) $row['seen_at'] <= ADMIN_IDLE_SECONDS && $now - (int) $row['created_at'] <= ADMIN_SESSION_SECONDS) {
        $session = $row;
        $db->prepare('UPDATE admin_sessions SET seen_at = ? WHERE token_hash = ?')->execute([$now, $row['token_hash']]);
    } elseif ($row) {
        $db->prepare('DELETE FROM admin_sessions WHERE token_hash = ?')->execute([$row['token_hash']]);
    }
}

// ---------------------------------------------------------------------------
// Signing in.
// ---------------------------------------------------------------------------
if ($session === null) {
    $err = null;
    if ($method === 'POST' && ($_POST['do'] ?? '') === 'login') {
        // Counted first, decided on the count: parallel tries can't all pass a
        // check that runs before any of them is counted.
        $ipBucket = "admin:login:ip:$rlIp";
        $ipTries  = $rl->hit($ipBucket, 900);
        $allTries = $rl->hit('admin:login:all', 3600);
        if ($ipTries > 5 || $allTries > 50) {
            // Refused at once, with no pause: a pause for every refused try
            // would let a flood of them hold all of the server's workers.
            // Logged once per address and window, not once per try.
            if ($ipTries === 6 || $allTries === 51) {
                $audit->log(null, null, $ip, 'admin_login', false, 'rate_limited');
            }
            $err = 'Too many failed tries. Wait a while, or use php bin/admin.php on the server.';
        } else {
            $given = is_string($_POST['password'] ?? null) ? $_POST['password'] : '';
            if (strlen($given) <= 1024 && !str_contains($given, "\0") && password_verify($given, $pwHash)) {
                $rl->reset($ipBucket);
                $token = Util::randomToken(32);
                $db->prepare('INSERT INTO admin_sessions (token_hash, csrf, pw_tag, ip_address, created_at, seen_at) VALUES (?, ?, ?, ?, ?, ?)')
                   ->execute([Util::hashToken($token, $pepper), Util::randomToken(32), $pwTag, mb_substr($ip, 0, 45), $now, $now]);
                $setCookie($token, 0);
                $audit->log(null, null, $ip, 'admin_login', true);
                admin_redirect($panel);
            }
            $audit->log(null, null, $ip, 'admin_login', false, 'bad_password');
            usleep(500000);
            $err = 'Wrong password.';
        }
    }
    if ($err !== null) http_response_code(401);
    admin_page('Submarine sync: admin', '<div class="card login"><h1>Submarine sync</h1><p class="muted">Admin panel</p>'
        . ($err !== null ? '<div class="flash err">' . h($err) . '</div>' : '')
        . '<form method="post" action="' . h($panel) . '"><input type="hidden" name="do" value="login">'
        . '<label for="pw">Admin password</label><input id="pw" type="password" name="password" autocomplete="current-password" autofocus required>'
        . '<button class="primary" type="submit">Sign in</button></form></div>', $nonce);
}

// ---------------------------------------------------------------------------
// Actions: POST with the CSRF token. Codes are shown once, at once; other
// actions end in a redirect so a reload never repeats them.
// ---------------------------------------------------------------------------
$csrf  = (string) $session['csrf'];
$admin = new Admin($db, $config, $audit, $ip);
$setFlash = static function (string $text) use ($db, $session): void {
    $db->prepare('UPDATE admin_sessions SET flash = ? WHERE token_hash = ?')->execute([mb_substr($text, 0, 255), $session['token_hash']]);
};
$q    = mb_substr(trim(is_string($_GET['q'] ?? null) ? $_GET['q'] : ''), 0, 100);
$page = max(1, min(100000, (int) ($_GET['page'] ?? 1)));
$self = $panel . ($q !== '' || $page > 1 ? '?' . http_build_query(array_filter(['q' => $q, 'page' => $page > 1 ? $page : null])) : '');
$hidden = static fn (array $f): string => implode('', array_map(
    static fn ($k, $v) => '<input type="hidden" name="' . h((string) $k) . '" value="' . h((string) $v) . '">', array_keys($f), $f));

$codeBox = null;
if ($method === 'POST') {
    $field = static fn (string $k): string => is_string($_POST[$k] ?? null) ? $_POST[$k] : '';
    $do = $field('do');
    if ($do === 'login') {
        admin_redirect($panel); // already signed in (another tab)
    }
    if (!hash_equals($csrf, $field('csrf'))) {
        $setFlash('That form was out of date. Try again.');
        admin_redirect($self);
    }
    $uid = ctype_digit($field('uid')) ? (int) $field('uid') : 0;
    try {
        switch ($do) {
            case 'logout':
                $db->prepare('DELETE FROM admin_sessions WHERE token_hash = ?')->execute([$session['token_hash']]);
                $setCookie('', 1);
                $audit->log(null, null, $ip, 'admin_logout', true);
                admin_redirect($panel);
            case 'invite':
                $r = $admin->invite($field('email'));
                $codeBox = ['Invitation for ' . $r['email'], $r['code'], $r['ttl'],
                    'In Submarine: Cloud sync, set the sync server to this one, choose "Have a verify token? Continue verifying", paste the code, then choose a password.'];
                break;
            case 'reset':
                $u = $admin->byId($uid);
                if (!$u) throw new InvalidArgumentException('There is no such account.');
                $r = $admin->resetCode($u['email']);
                $codeBox = ['Reset code for ' . $r['email'], $r['code'], $r['ttl'],
                    'In Submarine: Cloud sync, Sign in, "Forgot password?", "Already have a reset token? Continue", paste the code and choose a new password. Every device of the account is signed out.'];
                break;
            case 'suspend':
                $admin->suspend($uid);
                $setFlash('Suspended ' . ($admin->byId($uid)['email'] ?? '') . ' and signed it out everywhere.');
                admin_redirect($self);
            case 'unsuspend':
                $admin->unsuspend($uid);
                $setFlash(($admin->byId($uid)['email'] ?? 'The account') . ' can sign in again.');
                admin_redirect($self);
            case 'signout':
                $n = $admin->signOut($uid);
                $setFlash('Signed out of ' . $n . ' device' . ($n === 1 ? '' : 's') . '.');
                admin_redirect($self);
            case 'delete':
                $u = $admin->byId($uid);
                if (!$u) throw new InvalidArgumentException('There is no such account.');
                if (!hash_equals(strtolower($u['email']), strtolower(trim($field('confirm'))))) {
                    throw new InvalidArgumentException('Not deleted: type the account\'s email exactly to confirm.');
                }
                $admin->delete($uid);
                $setFlash('Deleted ' . $u['email'] . ' and everything it held.');
                admin_redirect($self);
            default:
                throw new InvalidArgumentException('Unknown action.');
        }
    } catch (InvalidArgumentException $e) {
        $setFlash($e->getMessage());
        admin_redirect($self);
    }
}

// ---------------------------------------------------------------------------
// The page.
// ---------------------------------------------------------------------------
$flash = $session['flash'] !== null ? (string) $session['flash'] : null;
if ($flash !== null) {
    $db->prepare('UPDATE admin_sessions SET flash = NULL WHERE token_hash = ?')->execute([$session['token_hash']]);
}

$t = $admin->totals();
$total = $admin->count($q);
$pages = max(1, (int) ceil($total / ADMIN_PAGE_SIZE));
$page = min($page, $pages);
$rows = $admin->list($q, ADMIN_PAGE_SIZE, ($page - 1) * ADMIN_PAGE_SIZE);
$form = static function (string $do, array $extra, string $label, string $class = '') use ($self, $csrf, $hidden): string {
    return '<form class="inline" method="post" action="' . h($self) . '">' . $hidden(['do' => $do, 'csrf' => $csrf] + $extra)
        . '<button type="submit"' . ($class !== '' ? ' class="' . $class . '"' : '') . '>' . h($label) . '</button></form>';
};

$html = '<div class="top"><div><h1>Submarine sync</h1><div class="muted">Admin panel. Accounts and sizes only; profiles stay encrypted.</div></div>'
    . $form('logout', [], 'Sign out') . '</div>';
if ($flash !== null) {
    $html .= '<div class="flash">' . h($flash) . '</div>';
}
if ($codeBox !== null) {
    [$title, $code, $ttl, $how] = $codeBox;
    $life = $ttl % 86400 === 0 ? ($ttl / 86400) . ' day' . ($ttl === 86400 ? '' : 's') : intdiv($ttl, 3600) . ' hours';
    $html .= '<div class="card"><h2>' . h($title) . '</h2><p class="muted">Give this code to the person. It works once, for '
        . h($life) . '. It is shown only now.</p><div class="code">' . h($code) . '</div><p>' . h($how) . '</p></div>';
}
$a = $t['accounts'];
$html .= '<div class="card stats">'
    . '<div class="stat"><b>' . number_format($a['active']) . '</b><span>active accounts</span></div>'
    . '<div class="stat"><b>' . number_format($a['pending']) . '</b><span>not finished</span></div>'
    . '<div class="stat"><b>' . number_format($a['banned']) . '</b><span>suspended</span></div>'
    . '<div class="stat"><b>' . number_format($t['profiles']) . '</b><span>personal profiles</span></div>'
    . '<div class="stat"><b>' . number_format($t['shares']) . '</b><span>shared profiles</span></div>'
    . '<div class="stat"><b>' . h(bytes_text($t['bytes'])) . '</b><span>stored, ' . number_format($t['records']) . ' records</span></div>'
    . '</div>';
$html .= '<div class="card"><h2>Invite someone</h2><form method="post" action="' . h($self) . '" class="row">' . $hidden(['do' => 'invite', 'csrf' => $csrf])
    . '<input type="email" name="email" placeholder="email address" required maxlength="191"><button class="primary" type="submit">Make an invitation code</button></form>'
    . '<p class="muted">Sign-up on this server: ' . ($config['signup'] === 'open' ? 'open to anyone (code by mail).' : 'by invitation only.') . '</p></div>';

$html .= '<div class="card"><div class="top"><h2>Accounts (' . number_format($total) . ')</h2><form method="get" action="' . h($panel) . '" class="row">'
    . '<input type="search" name="q" value="' . h($q) . '" placeholder="search email"><button type="submit">Search</button></form></div><div class="wrap"><table>'
    . '<tr><th>Email</th><th>Status</th><th>Created</th><th>Last seen</th><th>Profiles</th><th>Storage</th><th>Actions</th></tr>';
foreach ($rows as $u) {
    $status = $u['status'] === 'banned' ? 'suspended' : ($u['status'] === 'pending' ? 'not finished' : 'active');
    $seen = max((int) $u['last_seen'], (int) $u['last_login']) ?: null;
    $acts = '';
    if ($u['status'] === 'active') {
        $acts .= $form('reset', ['uid' => $u['id']], 'Reset code');
        $acts .= $form('signout', ['uid' => $u['id']], 'Sign out everywhere');
    }
    $acts .= $u['status'] === 'banned' ? $form('unsuspend', ['uid' => $u['id']], 'Unsuspend') : $form('suspend', ['uid' => $u['id']], 'Suspend');
    $acts .= '<form class="inline row" method="post" action="' . h($self) . '">' . $hidden(['do' => 'delete', 'csrf' => $csrf, 'uid' => $u['id']])
        . '<input type="text" name="confirm" placeholder="type the email to delete" autocomplete="off" size="22"><button class="danger" type="submit">Delete</button></form>';
    $html .= '<tr><td>' . h($u['email']) . '</td><td><span class="pill ' . h($u['status']) . '">' . h($status) . '</span></td>'
        . '<td>' . h(substr($u['created'], 0, 10)) . '</td><td>' . when_text($seen, $now) . '</td>'
        . '<td>' . (int) $u['profiles'] . '</td><td>' . h(bytes_text((int) $u['bytes'])) . '</td><td class="actions">' . $acts . '</td></tr>';
}
if (!$rows) {
    $html .= '<tr><td colspan="7" class="muted">No accounts' . ($q !== '' ? ' match.' : ' yet.') . '</td></tr>';
}
$html .= '</table></div>';
if ($pages > 1) {
    $link = static fn (int $p): string => h($panel . '?' . http_build_query(array_filter(['q' => $q, 'page' => $p])));
    $html .= '<div class="pager">' . ($page > 1 ? '<a href="' . $link($page - 1) . '">Newer</a>' : '')
        . '<span class="muted">Page ' . $page . ' of ' . $pages . '</span>'
        . ($page < $pages ? '<a href="' . $link($page + 1) . '">Older</a>' : '') . '</div>';
}
$html .= '</div>';
admin_page('Submarine sync: admin', $html, $nonce);
