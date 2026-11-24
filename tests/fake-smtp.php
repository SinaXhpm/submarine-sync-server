<?php
// A tiny SMTP server for the mail tests. It accepts any sign-in and writes
// each message it gets as one JSON line to <outfile>.
//
//   php tests/fake-smtp.php <port> <plain|starttls> <outfile> [cert.pem]
//
// plain:    STARTTLS is not offered.
// starttls: STARTTLS is offered (cert.pem holds a certificate and its key).
// bare:     like plain, but every answer ends with a line that is the code
//           alone ("250-ok", then "250"), which RFC 5321 4.2 allows.
declare(strict_types=1);

[$_, $port, $mode, $outfile] = $argv + [null, null, null, null];
$cert = $argv[4] ?? '';
$ctx = stream_context_create($mode === 'starttls' ? ['ssl' => ['local_cert' => $cert, 'verify_peer' => false, 'allow_self_signed' => true]] : []);
$srv = stream_socket_server("tcp://127.0.0.1:$port", $errno, $errstr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $ctx);
if (!$srv) {
    fwrite(STDERR, "listen failed: $errstr\n");
    exit(1);
}
echo "ready\n";

while (true) {
    $c = @stream_socket_accept($srv, 600);
    if (!$c) continue;
    stream_set_timeout($c, 10);
    $msg = ['tls' => false, 'auth' => null, 'auth_before_tls' => false, 'from' => null, 'to' => [], 'data' => null];
    $say = fn (string $s) => fwrite($c, ($mode === 'bare' ? preg_replace('/^(\d{3}) (.*)$/', "\$1-\$2\r\n\$1", $s) : $s) . "\r\n");
    $say('220 fake.test ESMTP');
    while (($line = fgets($c, 8192)) !== false) {
        $cmd = rtrim($line, "\r\n");
        $up = strtoupper($cmd);
        if (str_starts_with($up, 'EHLO') || str_starts_with($up, 'HELO')) {
            $say('250-fake.test');
            if ($mode === 'starttls' && !$msg['tls']) $say('250-STARTTLS');
            $say('250 AUTH PLAIN LOGIN');
        } elseif ($up === 'STARTTLS' && $mode === 'starttls') {
            $say('220 go ahead');
            $msg['tls'] = (bool) @stream_socket_enable_crypto($c, true, STREAM_CRYPTO_METHOD_TLS_SERVER);
            if (!$msg['tls']) break;
        } elseif (str_starts_with($up, 'AUTH PLAIN ')) {
            $parts = explode("\0", (string) base64_decode(substr($cmd, 11)));
            $msg['auth'] = [$parts[1] ?? '', $parts[2] ?? ''];
            $msg['auth_before_tls'] = !$msg['tls'];
            $say('235 ok');
        } elseif ($up === 'AUTH LOGIN') {
            $say('334 VXNlcm5hbWU6');
            $u = base64_decode(trim((string) fgets($c)));
            $say('334 UGFzc3dvcmQ6');
            $p = base64_decode(trim((string) fgets($c)));
            $msg['auth'] = [$u, $p];
            $msg['auth_before_tls'] = !$msg['tls'];
            $say('235 ok');
        } elseif (str_starts_with($up, 'MAIL FROM:')) {
            $msg['from'] = substr($cmd, 10);
            $say('250 ok');
        } elseif (str_starts_with($up, 'RCPT TO:')) {
            $msg['to'][] = substr($cmd, 8);
            $say('250 ok');
        } elseif ($up === 'DATA') {
            $say('354 go');
            $data = '';
            while (($l = fgets($c, 8192)) !== false && $l !== ".\r\n") $data .= $l;
            $msg['data'] = $data;
            $say('250 queued');
            file_put_contents($outfile, json_encode(['event' => 'message'] + $msg) . "\n", FILE_APPEND | LOCK_EX);
        } elseif ($up === 'QUIT') {
            $say('221 bye');
            break;
        } else {
            $say('502 no');
        }
    }
    @fclose($c);
    file_put_contents($outfile, json_encode(['event' => 'closed', 'tls' => $msg['tls'], 'auth' => $msg['auth']]) . "\n", FILE_APPEND | LOCK_EX);
}
