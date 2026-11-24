<?php
// Mail: what is sent, and that an SMTP password never goes out unencrypted
// unless the settings say 'none'. Uses tests/fake-smtp.php on two local ports.
//   php tests/mail-test.php
declare(strict_types=1);
require __DIR__ . '/lib.php';

wipe();
$dir = sys_get_temp_dir() . '/submarine-mail-test-' . bin2hex(random_bytes(4));
mkdir($dir, 0700);
$pem = "$dir/cert.pem";
exec('openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost -keyout ' . escapeshellarg("$dir/key.pem")
    . ' -out ' . escapeshellarg("$dir/crt.pem") . ' 2>/dev/null', $o, $rc);
file_put_contents($pem, file_get_contents("$dir/crt.pem") . file_get_contents("$dir/key.pem"));

$servers = [];
$start = function (int $port, string $mode, string $out) use (&$servers, $pem): void {
    $p = proc_open([PHP_BINARY, __DIR__ . '/fake-smtp.php', (string) $port, $mode, $out, $pem], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    fgets($pipes[1]); // "ready"
    $servers[] = $p;
};
register_shutdown_function(function () use (&$servers, $dir) {
    foreach ($servers as $p) { proc_terminate($p); }
    array_map('unlink', glob("$dir/*") ?: []);
    @rmdir($dir);
});
$plainOut = "$dir/plain.jsonl";
$tlsOut = "$dir/tls.jsonl";
$bareOut = "$dir/bare.jsonl";
$start(18125, 'plain', $plainOut);
$start(18126, 'starttls', $tlsOut);
$start(18127, 'bare', $bareOut);
$lines = function (string $f, string $event): array {
    if (!is_file($f)) return [];
    return array_values(array_filter(array_map(fn ($l) => json_decode($l, true), file($f, FILE_IGNORE_NEW_LINES)), fn ($m) => ($m['event'] ?? '') === $event));
};
$smtp = fn (int $port, string $security, array $more = []) => [
    'signup' => 'open',
    'mail' => $more + ['transport' => 'smtp', 'smtp_host' => '127.0.0.1', 'smtp_port' => $port, 'smtp_security' => $security,
                       'smtp_user' => 'mailer', 'smtp_password' => 'mail secret 1', 'smtp_verify_peer' => false,
                       'from_address' => 'sync@stage.test', 'from_name' => 'Test sync'],
];

// ===========================================================================
section('starttls (the default) refuses a server that does not offer it');
setConfig($smtp(18125, 'starttls'));
$r = req('POST', '/auth/signup', ['email' => 'one@stage.test']);
check('the sign-up is answered', [$r['code'], $r['json']['status'] ?? null], [200, 'pending']);
$ev = waitFor(fn () => one("SELECT detail FROM auth_events WHERE event = 'mail_failed' AND email = 'one@stage.test'"), 10);
check('the mail is not sent, and the log says why', str_contains((string) $ev, 'does not offer STARTTLS'), true);
$closed = waitFor(fn () => $lines($plainOut, 'closed'), 5);
check('the password never reached the server', [count($closed), array_key_exists('auth', $closed[0] ?? []) ? $closed[0]['auth'] : 'missing'], [1, null]);
check('no message', count($lines($plainOut, 'message')), 0);

section('starttls with a server that offers it');
setConfig($smtp(18126, 'starttls'));
$r = req('POST', '/auth/signup', ['email' => 'two@stage.test']);
$msg = waitFor(fn () => $lines($tlsOut, 'message'), 10);
$m = $msg[0] ?? [];
check('sent over TLS, signed in after TLS', [$m['tls'] ?? null, $m['auth'] ?? null, $m['auth_before_tls'] ?? null], [true, ['mailer', 'mail secret 1'], false]);
check('envelope', [$m['from'] ?? null, $m['to'] ?? null], ['<sync@stage.test>', ['<two@stage.test>']]);
$data = (string) ($m['data'] ?? '');
check('headers', [str_contains($data, 'From: "Test sync" <sync@stage.test>'), str_contains($data, 'To: <two@stage.test>'),
    str_contains($data, 'Subject: Your Submarine verification code'), str_contains($data, 'Auto-Submitted: auto-generated')], [true, true, true, true]);
preg_match('/^\s{4}([0-9a-f]{48})\r?$/m', $data, $code);
check('the code is in it, with how long it lasts', [strlen($code[1] ?? ''), str_contains($data, 'expires in 24 hours')], [48, true]);
$v = req('POST', '/auth/verify', ['token' => $code[1] ?? '']);
check('the mailed code verifies', $v['code'], 200);
$s = req('POST', '/auth/set-password', ['claim_token' => $v['json']['claim_token'] ?? '', 'password' => 'two password 1']);
check('and the account is finished: sign-up by mail works end to end', [$s['code'], one('SELECT status FROM users WHERE email = ?', ['two@stage.test'])], [200, 'active']);

section('reset and sign-in codes by mail');
clearRL();
req('POST', '/auth/request-reset', ['email' => 'two@stage.test']);
$msg = waitFor(fn () => count($lines($tlsOut, 'message')) >= 2 ? $lines($tlsOut, 'message') : [], 10);
$data = (string) ($msg[1]['data'] ?? '');
preg_match('/^\s{4}([0-9a-f]{48})\r?$/m', $data, $code);
check('a reset mail, 1 hour', [str_contains($data, 'Subject: Reset your Submarine sync password'), str_contains($data, 'expires in 1 hour')], [true, true]);
check('its code resets the password', req('POST', '/auth/reset-with-token', ['reset_token' => $code[1] ?? '', 'password' => 'two password 2'])['code'], 200);
clearRL();
req('POST', '/auth/request-login', ['email' => 'two@stage.test']);
$msg = waitFor(fn () => count($lines($tlsOut, 'message')) >= 3 ? $lines($tlsOut, 'message') : [], 10);
$data = (string) ($msg[2]['data'] ?? '');
preg_match('/^\s{4}([0-9a-f]{48})\r?$/m', $data, $code);
check('a sign-in mail, 15 minutes', [str_contains($data, 'Subject: Your Submarine sign-in code'), str_contains($data, 'expires in 15 minutes')], [true, true]);
check('its code signs in', req('POST', '/auth/login-with-link', ['login_token' => $code[1] ?? ''])['code'], 200);
clearRL();
req('POST', '/auth/request-login', ['email' => 'nobody@stage.test']);
usleep(1500000);
check('an unknown address gets no mail', count($lines($tlsOut, 'message')), 3);

section("security 'none' sends in the clear, as asked");
setConfig($smtp(18125, 'none'));
clearRL();
req('POST', '/auth/signup', ['email' => 'three@stage.test']);
$msg = waitFor(fn () => $lines($plainOut, 'message'), 10);
check('sent without TLS', [count($msg), $msg[0]['tls'] ?? null], [1, false]);
setConfig($smtp(18125, 'none', ['smtp_user' => '', 'smtp_password' => '']));
clearRL();
req('POST', '/auth/signup', ['email' => 'four@stage.test']);
$msg = waitFor(fn () => count($lines($plainOut, 'message')) >= 2 ? $lines($plainOut, 'message') : [], 10);
check('with no user name, no sign-in is tried', [count($msg), array_key_exists('auth', $msg[1] ?? []) ? $msg[1]['auth'] : 'missing'], [2, null]);

section('a server whose answers end with the code alone');
setConfig($smtp(18127, 'none'));
clearRL();
req('POST', '/auth/signup', ['email' => 'bare@stage.test']);
$msg = waitFor(fn () => $lines($bareOut, 'message'), 15);
check('the mail is sent, signed in, and nothing is logged as failed', [count($msg), $msg[0]['auth'] ?? null,
    (int) one("SELECT COUNT(*) FROM auth_events WHERE event = 'mail_failed' AND email = 'bare@stage.test'")], [1, ['mailer', 'mail secret 1'], 0]);

section('a first sharing key: the owner hears about it');
setConfig($smtp(18125, 'none'));
$ku = mkuser('keyowner@stage.test');
$r = api($ku, 'POST', '/keys/publish', ['public_key' => bin2hex(random_bytes(32)), 'wrapped_privkey' => bin2hex(random_bytes(48)), 'enc_salt' => bin2hex(random_bytes(16))]);
$msg = waitFor(fn () => count($lines($plainOut, 'message')) >= 3 ? $lines($plainOut, 'message') : [], 10);
$data = (string) ($msg[2]['data'] ?? '');
check('the key is set up, and a note goes to the account\'s email',
    [$r['code'], $msg[2]['to'] ?? null, str_contains($data, 'Subject: A sharing key was set up for your Submarine sync account')], [200, ['<keyowner@stage.test>'], true]);

section('a name with a line break can not add a header');
setConfig($smtp(18126, 'starttls', ['from_name' => "Sync\r\nBcc: victim@stage.test"]));
clearRL();
req('POST', '/auth/signup', ['email' => 'five@stage.test']);
$msg = waitFor(fn () => count($lines($tlsOut, 'message')) >= 4 ? $lines($tlsOut, 'message') : [], 10);
$data = (string) ($msg[3]['data'] ?? '');
check('no Bcc header', [strlen($data) > 0, (bool) preg_match('/^Bcc:/mi', $data)], [true, false]);

section('codes and addresses never reach the server log');
$log = (string) getenv('SUBMARINE_TEST_SERVER_LOG');
if ($log !== '' && is_readable($log)) {
    setConfig(['signup' => 'open', 'mail' => ['transport' => 'smtp', 'smtp_host' => '127.0.0.1', 'smtp_port' => 9, 'smtp_security' => 'none', 'from_address' => 'sync@stage.test']]);
    $before = filesize($log);
    clearRL();
    req('POST', '/auth/signup', ['email' => 'logcheck@stage.test']);
    usleep(1500000);
    clearstatcache();
    $text = (string) file_get_contents($log, false, null, $before);
    $codes = array_column(rows('SELECT token_hash FROM verify_tokens'), 'token_hash');
    check('the failed send is logged, without the address', [str_contains($text, 'mail not sent'), str_contains($text, 'logcheck@stage.test')], [true, false]);
    $all = '';
    foreach ($lines($tlsOut, 'message') as $m) $all .= $m['data'];
    preg_match_all('/^\s{4}([0-9a-f]{48})\r?$/m', $all, $mm);
    $wholeLog = (string) file_get_contents($log);
    check('no mailed code is in the log', array_values(array_filter($mm[1], fn ($c) => str_contains($wholeLog, $c))), []);
} else {
    echo "      (skipped: set SUBMARINE_TEST_SERVER_LOG to the server's error log)\n";
}

done();
