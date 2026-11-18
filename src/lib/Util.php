<?php
// Submarine sync server — small helpers used everywhere.

declare(strict_types=1);

namespace Submarine\Lib;

final class Util
{
    /**
     * The stored form of a token (sign-in token, one-time code): an HMAC with
     * the server's secret pepper. The raw token is never stored, so a copy of
     * the database alone can't be used to sign in.
     */
    public static function hashToken(string $raw, string $pepper): string
    {
        return hash_hmac('sha256', $raw, $pepper);
    }

    /**
     * Set by the sync endpoints (POST /sync, POST /shares/sync), whose bodies
     * and answers carry whole record sets: they take a gzipped request body,
     * say so with an `Accept-Encoding: gzip` response header (RFC 7694), and
     * gzip a big answer for a client that asks for it. Every other endpoint
     * stays plain: no answer that carries a token or a password is compressed.
     */
    private static bool $compression = false;

    public static function enableCompression(): void
    {
        self::$compression = true;
    }

    /** Whether the client's Accept-Encoding takes gzip (q above 0). */
    private static function clientTakesGzip(): bool
    {
        foreach (explode(',', (string) ($_SERVER['HTTP_ACCEPT_ENCODING'] ?? '')) as $part) {
            $bits = array_map('trim', explode(';', $part));
            if (strtolower($bits[0]) !== 'gzip') {
                continue;
            }
            $q = 1.0;
            foreach (array_slice($bits, 1) as $param) {
                if (stripos($param, 'q=') === 0) {
                    $q = (float) substr($param, 2);
                }
            }
            return $q > 0;
        }
        return false;
    }

    /** Send a JSON answer and stop. */
    public static function sendJson(int $code, array $body): never
    {
        $json = (string) json_encode($body, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        self::jsonHeaders($code);
        if (self::$compression && strlen($json) >= 1024 && !headers_sent() && self::clientTakesGzip()) {
            $gz = gzencode($json, 6);
            if ($gz !== false) {
                header('Content-Encoding: gzip');
                header('Content-Length: ' . strlen($gz));
                echo $gz;
                exit;
            }
        }
        echo $json;
        exit;
    }

    /**
     * Send a JSON answer and go on running: the client has its answer at
     * once, and slow work after it (sending mail) can't be timed from the
     * outside, where it would tell a registered email from an unknown one.
     * The caller exits when it's done.
     */
    public static function sendJsonThenContinue(int $code, array $body): void
    {
        ignore_user_abort(true);
        $json = (string) json_encode($body, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        self::jsonHeaders($code);
        if (function_exists('fastcgi_finish_request')) {
            echo $json;
            fastcgi_finish_request();
            return;
        }
        if (!headers_sent()) {
            header('Content-Length: ' . strlen($json));
            header('Connection: close');
        }
        echo $json;
        while (ob_get_level() > 0) {
            ob_end_flush();
        }
        flush();
    }

    private static function jsonHeaders(int $code): void
    {
        http_response_code($code);
        if (!headers_sent()) {
            header('Content-Type: application/json');
            header('Cache-Control: no-store');
            header('X-Content-Type-Options: nosniff');
            header('Referrer-Policy: no-referrer');
            header('X-Frame-Options: DENY');
            header("Content-Security-Policy: default-src 'none'; frame-ancestors 'none'");
            header('Strict-Transport-Security: max-age=63072000');
            header_remove('X-Powered-By');
            if (self::$compression) {
                header('Accept-Encoding: gzip');
                header('Vary: Accept-Encoding');
            }
        }
    }

    /** The error shape every endpoint uses: { error, message, ...extra }. */
    public static function sendError(int $code, string $error, string $msg = '', array $extra = []): never
    {
        self::sendJson($code, array_merge(['error' => $error, 'message' => $msg], $extra));
    }

    /**
     * The JSON body, decoded. Refuses a body that is too big, not JSON, or
     * compressed where the endpoint doesn't take that.
     */
    public static function readJson(int $maxBytes): array
    {
        $len = (int) ($_SERVER['CONTENT_LENGTH'] ?? 0);
        if ($len > $maxBytes) {
            self::sendError(413, 'body_too_large', "Body exceeds {$maxBytes} bytes");
        }
        // JSON bodies only. Another web page can make a visitor's browser
        // POST a form or text/plain body here without asking first, but not
        // an application/json one, so such a POST never reaches a handler.
        $type   = (string) ($_SERVER['CONTENT_TYPE'] ?? ($_SERVER['HTTP_CONTENT_TYPE'] ?? ''));
        $isJson = strtolower(trim(explode(';', $type)[0])) === 'application/json';
        if ($len > 0 && !$isJson) {
            self::sendError(415, 'unsupported_media_type', 'Send the body as application/json');
        }
        $encoding = strtolower(trim((string) ($_SERVER['HTTP_CONTENT_ENCODING'] ?? '')));
        $gzipped  = $encoding === 'gzip';
        if ($encoding !== '' && $encoding !== 'identity' && !($gzipped && self::$compression)) {
            self::sendError(415, 'unsupported_content_encoding', 'Send the body uncompressed');
        }
        $raw = file_get_contents('php://input', false, null, 0, $maxBytes + 1);
        if ($raw === '' || $raw === false) {
            return [];
        }
        if (strlen($raw) > $maxBytes) {
            self::sendError(413, 'body_too_large', "Body exceeds {$maxBytes} bytes");
        }
        if (!$isJson) {
            // A body sent without a Content-Length (chunked).
            self::sendError(415, 'unsupported_media_type', 'Send the body as application/json');
        }
        if ($gzipped) {
            // The cap stops a small body that inflates to gigabytes early; it
            // isn't exact, so the size is checked again after.
            $raw = @gzdecode($raw, $maxBytes);
            if ($raw === false) {
                self::sendError(400, 'bad_body', 'The gzipped body could not be read, or is too large');
            }
            if (strlen($raw) > $maxBytes) {
                self::sendError(413, 'body_too_large', "Body exceeds {$maxBytes} bytes");
            }
        }
        if (!self::jsonShapeOk($raw)) {
            self::sendError(400, 'bad_body', 'The body has an object with too many keys');
        }
        $decoded = json_decode($raw, true, 512);
        return is_array($decoded) ? $decoded : [];
    }

    /** Most keys one JSON object may have (see jsonShapeOk). */
    public const MAX_OBJECT_KEYS = 1000;

    /** Deepest nesting a body may have. Real ones go about six deep. */
    private const MAX_JSON_DEPTH = 64;

    /**
     * False for a JSON body with an object that has an absurd number of keys.
     * PHP builds an object's keys into one hash table, and keys picked to
     * collide make that quadratic: a 4 MB body with about 100,000 of them took
     * 34 seconds of a worker. Nothing this API takes has an object with more
     * than a few dozen keys, so one with a thousand is refused before
     * json_decode runs. One linear pass; a body under 16 KB skips it.
     */
    public static function jsonShapeOk(string $raw): bool
    {
        $len = strlen($raw);
        if ($len < 16384) {
            return true;
        }
        $keys = [];
        $isObject = [];
        $depth = 0;
        $i = 0;
        while ($i < $len) {
            $i += strcspn($raw, '"{}[]', $i);
            if ($i >= $len) {
                break;
            }
            $c = $raw[$i];
            if ($c === '"') {
                $j = $i + 1;
                while (true) {
                    $j = strpos($raw, '"', $j);
                    if ($j === false) {
                        return true; // not JSON; json_decode says so
                    }
                    $backslashes = 0;
                    for ($k = $j - 1; $k > $i && $raw[$k] === '\\'; $k--) {
                        $backslashes++;
                    }
                    if ($backslashes % 2 === 0) {
                        break;
                    }
                    $j++;
                }
                if ($depth > 0 && $isObject[$depth]) {
                    $n = $j + 1;
                    while ($n < $len && ($raw[$n] === ' ' || $raw[$n] === "\n" || $raw[$n] === "\r" || $raw[$n] === "\t")) {
                        $n++;
                    }
                    if ($n < $len && $raw[$n] === ':' && ++$keys[$depth] > self::MAX_OBJECT_KEYS) {
                        return false;
                    }
                }
                $i = $j + 1;
            } elseif ($c === '{' || $c === '[') {
                if (++$depth > self::MAX_JSON_DEPTH) {
                    return false;
                }
                $isObject[$depth] = ($c === '{');
                $keys[$depth] = 0;
                $i++;
            } else {
                if ($depth > 0) {
                    $depth--;
                }
                $i++;
            }
        }
        return true;
    }

    /** Hex token of N random bytes. */
    public static function randomToken(int $bytes = 32): string
    {
        return bin2hex(random_bytes($bytes));
    }

    /**
     * The client's address. REMOTE_ADDR, unless the request came from a
     * trusted proxy (security.trusted_proxies): then the address the proxy
     * names in `client_ip_header`.
     *
     * X-Forwarded-For is a list that every proxy adds to, and its left end is
     * whatever the client wrote. It is read from the right: the first address
     * that is not a trusted proxy is the client.
     */
    public static function clientIp(array $config): string
    {
        $remote  = (string) ($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
        $trusted = (array) ($config['security']['trusted_proxies'] ?? []);
        $header  = (string) ($config['security']['client_ip_header'] ?? 'X-Forwarded-For');
        $value   = trim((string) ($_SERVER['HTTP_' . strtoupper(str_replace('-', '_', $header))] ?? ''));
        // Without the header there is nothing to believe (and no host name to look up).
        if ($value === '' || !$trusted || !self::isTrustedProxy($remote, $trusted)) {
            return $remote;
        }
        if ($header !== 'X-Forwarded-For') {
            return filter_var($value, FILTER_VALIDATE_IP) ? $value : $remote;
        }
        $chain = array_map('trim', explode(',', $value));
        for ($i = count($chain) - 1; $i >= 0; $i--) {
            $hop = self::stripPort($chain[$i]);
            if (!filter_var($hop, FILTER_VALIDATE_IP)) {
                // A hop we can't read: whatever is left of it can't be trusted.
                return $i === count($chain) - 1 ? $remote : self::stripPort($chain[$i + 1]);
            }
            if (!self::isTrustedProxy($hop, $trusted)) {
                return $hop;
            }
        }
        // Every hop is one of our proxies: the left-most one is the closest
        // thing to a client there is.
        return self::stripPort($chain[0]);
    }

    /** "[2001:db8::1]:443" or "203.0.113.5:443" without the port. */
    private static function stripPort(string $hop): string
    {
        if (preg_match('/^\[([0-9A-Fa-f:.]+)\](?::\d+)?$/', $hop, $m)) {
            return $m[1];
        }
        if (preg_match('/^(\d{1,3}(?:\.\d{1,3}){3}):\d+$/', $hop, $m)) {
            return $m[1];
        }
        return $hop;
    }

    /** Whether the request came over HTTPS, here or at a trusted proxy. */
    public static function isHttps(array $config): bool
    {
        $https = strtolower((string) ($_SERVER['HTTPS'] ?? ''));
        if ($https !== '' && $https !== 'off') {
            return true;
        }
        $trusted = (array) ($config['security']['trusted_proxies'] ?? []);
        $remote  = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
        // The right-most value is the one our own proxy added; anything left
        // of it came from further away (or from the client).
        $parts   = explode(',', (string) ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? ''));
        $proto   = strtolower(trim((string) end($parts)));
        return $proto === 'https' && $trusted && self::isTrustedProxy($remote, $trusted);
    }

    /**
     * In the Docker image (SUBMARINE_IN_DOCKER=1): the container's default
     * gateway, the address connections from the host machine to the
     * published port arrive from. Null anywhere else, and when it can't be
     * read: outside a container, the default gateway is a router.
     */
    public static function dockerGateway(): ?string
    {
        static $gw = false;
        if ($gw !== false) {
            return $gw;
        }
        $gw = null;
        if (getenv('SUBMARINE_IN_DOCKER') !== '1') {
            return $gw;
        }
        foreach (@file('/proc/net/route', FILE_IGNORE_NEW_LINES) ?: [] as $line) {
            $f = preg_split('/\s+/', trim($line));
            // Destination 0.0.0.0 is the default route; the gateway is a
            // 32-bit number in the machine's own byte order.
            if (($f[1] ?? '') === '00000000' && preg_match('/^[0-9A-Fa-f]{8}$/', $f[2] ?? '') && $f[2] !== '00000000') {
                $gw = (string) inet_ntop(pack('L', hexdec($f[2])));
                break;
            }
        }
        return $gw;
    }

    /** Whether an address is one of the trusted proxies (IP, CIDR or host name). */
    public static function isTrustedProxy(string $ip, array $trusted): bool
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }
        // A proxy named by host name (Docker's "caddy") lives on a private
        // network. Only a peer with a private or loopback address can be it,
        // so a request from the internet never causes a name lookup.
        $private = !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
        foreach ($trusted as $entry) {
            $entry = (string) $entry;
            if (filter_var($entry, FILTER_VALIDATE_IP) || str_contains($entry, '/')) {
                if (self::ipInCidr($ip, $entry)) return true;
                continue;
            }
            if (!$private) {
                continue;
            }
            foreach (self::resolve($entry) as $addr) {
                if ($addr === $ip) return true;
            }
        }
        return false;
    }

    /** A host name's addresses, looked up once per request. */
    private static function resolve(string $host): array
    {
        static $cache = [];
        if (!isset($cache[$host])) {
            $v4 = @gethostbynamel($host) ?: [];
            $v6 = [];
            $recs = @dns_get_record($host, DNS_AAAA);
            if (is_array($recs)) {
                foreach ($recs as $r) {
                    if (!empty($r['ipv6'])) $v6[] = (string) inet_ntop((string) inet_pton($r['ipv6']));
                }
            }
            $cache[$host] = array_merge($v4, $v6);
        }
        return $cache[$host];
    }

    /**
     * The address a per-IP limit counts against. An IPv6 user usually holds
     * a whole /64 and can send from any address in it, so a limit counts the
     * /64; an IPv4 address (or one written IPv4-mapped) counts as itself.
     */
    public static function rateKeyIp(string $ip): string
    {
        $bin = @inet_pton($ip);
        if ($bin === false || strlen($bin) !== 16) {
            return $ip;
        }
        if (substr($bin, 0, 12) === str_repeat("\0", 10) . "\xff\xff") {
            return (string) inet_ntop(substr($bin, 12));
        }
        return inet_ntop(substr($bin, 0, 8) . str_repeat("\0", 8)) . '/64';
    }

    /** Whether $ip is the address $cidr, or inside the range $cidr. */
    public static function ipInCidr(string $ip, string $cidr): bool
    {
        if (strpos($cidr, '/') === false) {
            $a = @inet_pton($ip);
            $b = @inet_pton($cidr);
            return $a !== false && $b !== false && $a === $b;
        }
        [$network, $prefix] = explode('/', $cidr, 2);
        $ipBin  = @inet_pton($ip);
        $netBin = @inet_pton($network);
        if ($ipBin === false || $netBin === false || strlen($ipBin) !== strlen($netBin) || !ctype_digit($prefix)) {
            return false;
        }
        $prefix = (int) $prefix;
        if ($prefix > strlen($ipBin) * 8) {
            return false;
        }
        $wholeBytes = intdiv($prefix, 8);
        $extraBits  = $prefix % 8;
        if ($wholeBytes > 0 && substr($ipBin, 0, $wholeBytes) !== substr($netBin, 0, $wholeBytes)) {
            return false;
        }
        if ($extraBits === 0) {
            return true;
        }
        $mask = (0xff << (8 - $extraBits)) & 0xff;
        return (ord($ipBin[$wholeBytes]) & $mask) === (ord($netBin[$wholeBytes]) & $mask);
    }

    /**
     * Hold the answer until the request is $floorMs old. Answers that must not
     * tell whether an email has an account (a failed sign-in, the signup /
     * reset / sign-in-link "check your inbox") then all leave at the same
     * moment, whatever work their branch did.
     */
    public static function holdUntil(int $floorMs): void
    {
        $start = (float) ($_SERVER['REQUEST_TIME_FLOAT'] ?? microtime(true));
        $wait  = $start + $floorMs / 1000 - microtime(true);
        if ($wait > 0) {
            usleep((int) ($wait * 1000000));
        }
    }

    /** A short random pause, where an answer already differs by its content. */
    public static function constantTimeJitter(int $minMs = 80, int $maxMs = 220): void
    {
        usleep(random_int($minMs * 1000, $maxMs * 1000));
    }

    /**
     * An email address as the API takes it: 191 characters at most, printable
     * ASCII in the plain form (the one HTML forms take). FILTER_VALIDATE_EMAIL
     * alone also takes quoted names with control characters in them, which
     * would reach the admin's terminal (bin/admin.php list), the mail headers
     * and other members' screens.
     */
    public static function validEmail(string $email): bool
    {
        if (strlen($email) > 191) return false;
        if (!preg_match('/^[A-Za-z0-9.!#$%&\'*+\/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\z/', $email)) {
            return false;
        }
        return (bool) filter_var($email, FILTER_VALIDATE_EMAIL);
    }

    /**
     * A sync record's `updated_at` as the app writes it: an HLC stamp,
     * "{ms:015}:{counter:05}:{node}". Last-write-wins compares these as
     * strings, so a stamp in any other shape, or one from a clock more than
     * a day ahead, would beat every real edit to that record for good.
     */
    public static function validSyncStamp(string $uat): bool
    {
        if (!preg_match('/^(\d{15}):\d{5}:[0-9A-Za-z]{1,26}\z/', $uat, $m)) {
            return false;
        }
        return (int) $m[1] <= (int) (microtime(true) * 1000) + 86400000;
    }

    /**
     * A field of a JSON body as a string: '' for anything that isn't one
     * (an array, a number, null), so no code path ever turns ["x"] into
     * "Array" or warns about it.
     */
    public static function str(array $body, string $key): string
    {
        $v = $body[$key] ?? '';
        return is_string($v) ? $v : '';
    }

    /**
     * A new password the server takes: long enough, no NUL, and at most 72
     * bytes, because bcrypt ignores everything after the 72nd byte (a longer
     * one would sign in with only its first 72 bytes typed).
     */
    public static function passwordProblem(string $password, int $min): ?string
    {
        if (strlen($password) < $min) {
            return "The password needs $min characters or more.";
        }
        if (strlen($password) > 72) {
            return 'The password is too long: 72 bytes at most (fewer letters outside A-Z, which take 2 to 4 bytes each).';
        }
        if (str_contains($password, "\0")) {
            return 'The password has a character that is not allowed.';
        }
        return null;
    }
}
