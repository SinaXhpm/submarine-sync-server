<?php
// Submarine sync server — the account emails (verification, password reset,
// sign-in code), sent over SMTP or with PHP's mail().
//
// SMTP security (mail.smtp_security):
//   'starttls' — plain connection, then STARTTLS. If the server doesn't offer
//                it, nothing is sent: the password would otherwise go out
//                unencrypted, and an attacker on the way can hide the offer.
//   'tls'      — TLS from the first byte (usually port 465).
//   'none'     — no encryption. Only for a relay on the same machine or a
//                private network.
// A user name is optional; without one the server is not asked to sign in.

declare(strict_types=1);

namespace Submarine\Lib;

final class Mailer
{
    public function __construct(private array $config, private Audit $audit)
    {
    }

    public function enabled(): bool
    {
        return ($this->config['mail']['transport'] ?? 'off') !== 'off';
    }

    private static function duration(int $seconds): string
    {
        if ($seconds % 86400 === 0) {
            $d = intdiv($seconds, 86400);
            return $d === 1 ? '24 hours' : "$d days";
        }
        if ($seconds % 3600 === 0) {
            $h = intdiv($seconds, 3600);
            return $h === 1 ? '1 hour' : "$h hours";
        }
        return max(1, intdiv($seconds, 60)) . ' minutes';
    }

    public function sendVerify(string $to, string $token, string $ip): bool
    {
        $ttl = self::duration((int) $this->config['limits']['verify_token_ttl']);
        return $this->send($to, 'Your Submarine verification code', [
            'Hi,',
            '',
            'Use this code to verify your Submarine sync account:',
            '',
            '    ' . $token,
            '',
            'Paste it into the app, where it asks for the verify token.',
            '',
            "The code works once and expires in $ttl. If you didn't sign up, ignore this email.",
        ], $ip);
    }

    public function sendReset(string $to, string $token, string $ip): bool
    {
        $ttl = self::duration((int) $this->config['limits']['reset_token_ttl']);
        return $this->send($to, 'Reset your Submarine sync password', [
            'Hi,',
            '',
            'Someone, hopefully you, asked to reset the password of your Submarine sync',
            'account. Use this code in the app to set a new password:',
            '',
            '    ' . $token,
            '',
            "The code works once and expires in $ttl. If you didn't ask for it, ignore this",
            'email: your account stays as it was.',
            '',
            'A new password signs every device out. Your profiles stay encrypted with their',
            'own passwords; this one only opens the sync account.',
        ], $ip);
    }

    public function sendLoginLink(string $to, string $token, string $ip): bool
    {
        $ttl = self::duration((int) $this->config['limits']['login_token_ttl']);
        return $this->send($to, 'Your Submarine sign-in code', [
            'Hi,',
            '',
            'Use this code to sign in to Submarine sync on your device:',
            '',
            '    ' . $token,
            '',
            "The code works once and expires in $ttl. If you didn't ask for it, ignore this email.",
        ], $ip);
    }

    /** Told to the account when its sharing key is set up for the first time. */
    public function sendKeyNotice(string $to, string $ip): bool
    {
        return $this->send($to, 'A sharing key was set up for your Submarine sync account', [
            'Hi,',
            '',
            'A sharing key was just set up for your Submarine sync account, from the',
            'address ' . preg_replace('/[^0-9A-Fa-f:.]/', '', $ip) . ' at ' . gmdate('Y-m-d H:i') . ' UTC.',
            'Profiles that others share with you are sealed to this key.',
            '',
            "If that was you (choosing a sharing passphrase in the app), there's nothing to do.",
            "If it wasn't, someone else is signed in to your account: set a new password",
            '("Forgot password?" in the app), which signs every device out, and tell the',
            "server's admin.",
        ], $ip);
    }

    /** @param string[] $lines */
    private function send(string $to, string $subject, array $lines, string $ip): bool
    {
        $cfg = $this->config['mail'];
        if (!$this->enabled()) {
            // Neither the address nor the code is logged: whoever reads the log could use it.
            error_log('[submarine] mail is off: nothing sent');
            return false;
        }
        if (!filter_var($to, FILTER_VALIDATE_EMAIL)) {
            $this->audit->log(null, $to, $ip, 'mail_failed', false, 'invalid_recipient');
            return false;
        }
        $lines[] = '';
        $lines[] = '— ' . ($cfg['from_name'] !== '' ? $cfg['from_name'] : 'Submarine sync');
        $body = implode("\r\n", $lines);
        try {
            if ($cfg['transport'] === 'smtp') {
                $this->smtpSend($cfg, $to, $subject, $body);
            } else {
                $this->phpMail($cfg, $to, $subject, $body);
            }
            return true;
        } catch (\Throwable $e) {
            error_log('[submarine] mail not sent: ' . $e->getMessage());
            $this->audit->log(null, $to, $ip, 'mail_failed', false, mb_substr($e->getMessage(), 0, 200));
            return false;
        }
    }

    private function headers(array $cfg, string $to, string $subject, bool $withToAndSubject): array
    {
        $from = (string) $cfg['from_address'];
        $h = [
            'From: ' . $this->encodedDisplay((string) $cfg['from_name']) . ' <' . $from . '>',
            'Date: ' . date('r'),
            'Message-ID: <' . bin2hex(random_bytes(12)) . '@' . $this->messageDomain($cfg) . '>',
            'MIME-Version: 1.0',
            'Content-Type: text/plain; charset=UTF-8',
            'Content-Transfer-Encoding: 8bit',
            'Auto-Submitted: auto-generated',
        ];
        if ($withToAndSubject) {
            array_unshift($h, 'To: <' . $to . '>', 'Subject: ' . $this->encodedSubject($subject));
        }
        return $h;
    }

    private function phpMail(array $cfg, string $to, string $subject, string $body): void
    {
        if (!function_exists('mail')) {
            throw new \RuntimeException('PHP mail() is not available on this host');
        }
        $headers = implode("\r\n", $this->headers($cfg, $to, $subject, false));
        // -f sets the envelope sender, which SPF checks. from_address passed
        // FILTER_VALIDATE_EMAIL (Config::problems) and is quoted for the shell.
        $ok = @mail($to, $this->encodedSubject($subject), $body, $headers, '-f ' . escapeshellarg((string) $cfg['from_address']));
        if (!$ok) {
            throw new \RuntimeException('mail() returned false (the host\'s mail system refused it)');
        }
    }

    private function smtpSend(array $cfg, string $to, string $subject, string $body): void
    {
        $host     = (string) $cfg['smtp_host'];
        $port     = (int) $cfg['smtp_port'];
        $security = (string) $cfg['smtp_security'];
        $verify   = (bool) $cfg['smtp_verify_peer'];
        $context  = stream_context_create(['ssl' => [
            'verify_peer'      => $verify,
            'verify_peer_name' => $verify,
            'peer_name'        => $host,
            'SNI_enabled'      => true,
        ]]);
        $endpoint = ($security === 'tls' ? 'tls://' : 'tcp://') . "$host:$port";
        $sock = @stream_socket_client($endpoint, $errno, $errstr, 10, STREAM_CLIENT_CONNECT, $context);
        if (!$sock) {
            throw new \RuntimeException("could not connect to $host:$port ($errstr)");
        }
        try {
            stream_set_timeout($sock, 10);
            $this->expect($sock, 220);
            $name = $this->helloName($cfg);
            $this->write($sock, "EHLO $name");
            $ehlo = $this->expect($sock, 250);
            if ($security === 'starttls') {
                if (!preg_match('/^250[ -]STARTTLS\b/mi', $ehlo)) {
                    throw new \RuntimeException('the mail server does not offer STARTTLS; nothing was sent (set the security to tls or none if that is right)');
                }
                $this->write($sock, 'STARTTLS');
                $this->expect($sock, 220);
                if (!@stream_socket_enable_crypto($sock, true, STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT)) {
                    throw new \RuntimeException('the TLS handshake with the mail server failed');
                }
                $this->write($sock, "EHLO $name");
                $ehlo = $this->expect($sock, 250);
            }
            $user = (string) $cfg['smtp_user'];
            if ($user !== '') {
                $pass = (string) $cfg['smtp_password'];
                if (preg_match('/^250[ -]AUTH\b[^\r\n]*\bPLAIN\b/mi', $ehlo)) {
                    $this->write($sock, 'AUTH PLAIN ' . base64_encode("\0$user\0$pass"));
                    $this->expect($sock, 235);
                } else {
                    $this->write($sock, 'AUTH LOGIN');
                    $this->expect($sock, 334);
                    $this->write($sock, base64_encode($user));
                    $this->expect($sock, 334);
                    $this->write($sock, base64_encode($pass));
                    $this->expect($sock, 235);
                }
            }
            $from = (string) $cfg['from_address'];
            $this->write($sock, "MAIL FROM:<$from>");
            $this->expect($sock, 250);
            $this->write($sock, "RCPT TO:<$to>");
            $this->expect($sock, 250, 251);
            $this->write($sock, 'DATA');
            $this->expect($sock, 354);
            $message = implode("\r\n", $this->headers($cfg, $to, $subject, true)) . "\r\n\r\n" . $body;
            $message = preg_replace('/^\./m', '..', $message); // RFC 5321 4.5.2
            $this->write($sock, $message);
            $this->write($sock, '.');
            $this->expect($sock, 250);
            @fwrite($sock, "QUIT\r\n");
        } finally {
            @fclose($sock);
        }
    }

    private function expect($sock, int ...$expected): string
    {
        $buf = '';
        while (true) {
            $line = fgets($sock, 2048);
            if ($line === false) {
                throw new \RuntimeException('the mail server did not answer in time');
            }
            $buf .= $line;
            if (strlen($line) < 4) {
                throw new \RuntimeException('the mail server sent an answer that could not be read');
            }
            if ($line[3] === ' ') break;
            if (strlen($buf) > 65536) {
                throw new \RuntimeException('the mail server sent too long an answer');
            }
        }
        $code = (int) substr($buf, 0, 3);
        if (!in_array($code, $expected, true)) {
            throw new \RuntimeException('the mail server said: ' . trim(mb_substr($buf, 0, 300)));
        }
        return $buf;
    }

    private function write($sock, string $line): void
    {
        if (@fwrite($sock, $line . "\r\n") === false) {
            throw new \RuntimeException('could not write to the mail server');
        }
    }

    private function helloName(array $cfg): string
    {
        $h = gethostname();
        if (is_string($h) && preg_match('/^[A-Za-z0-9.-]+\.[A-Za-z0-9-]+$/', $h)) return $h;
        return $this->messageDomain($cfg);
    }

    private function messageDomain(array $cfg): string
    {
        $from = (string) $cfg['from_address'];
        $at = strrpos($from, '@');
        return $at !== false ? substr($from, $at + 1) : 'localhost';
    }

    private function encodedSubject(string $s): string
    {
        $s = str_replace(["\r", "\n", "\0"], '', $s);
        return preg_match('/[\x80-\xff]/', $s) ? '=?UTF-8?B?' . base64_encode($s) . '?=' : $s;
    }

    private function encodedDisplay(string $s): string
    {
        $s = str_replace(["\r", "\n", "\0"], '', $s);
        if (preg_match('/[\x80-\xff]/', $s)) {
            return '=?UTF-8?B?' . base64_encode($s) . '?=';
        }
        return '"' . str_replace(['\\', '"'], ['\\\\', '\\"'], $s) . '"';
    }
}
