<?php
// Submarine sync server — settings for a plain PHP host.
//
// Copy this file to config.php (next to it, outside public/) and fill it in.
// Anything you leave out keeps its default (see src/lib/Config.php).
// Environment variables (SUBMARINE_*) override what is here; Docker uses those
// instead of this file.

return [
    'db' => [
        'host'     => 'localhost',
        'port'     => 3306,
        'name'     => 'submarine',
        'user'     => 'submarine',
        'password' => '',
    ],

    'security' => [
        // A random secret of 32+ characters. Make one with: openssl rand -hex 32
        // Keep it: changing it later signs everybody out.
        'token_pepper' => '',

        // Reverse proxies in front of this server (IP addresses, CIDR ranges or
        // host names), and the header in which they name the client's address.
        // Leave empty when clients connect straight to this server.
        'trusted_proxies'  => [],
        'client_ip_header' => 'X-Forwarded-For',  // or 'X-Real-IP', 'CF-Connecting-IP'
    ],

    // 'invite': only people you invite (php bin/admin.php invite <email>, or the
    // admin panel) can make an account; no mail is needed.
    // 'open': anyone can sign up in the app; needs mail for their code.
    'signup' => 'invite',

    // Most accounts this server holds (0: no limit).
    'max_accounts' => 0,

    // The path the server answers under, when it is not the root of its host
    // name, for example '/submarine'. The app's sync server address is then
    // https://example.com/submarine
    'base_path' => '',

    'mail' => [
        'transport'     => 'off',        // 'off', 'smtp', or 'mail' (PHP's mail())
        'from_address'  => '',           // e.g. 'sync@example.com'
        'from_name'     => 'Submarine sync',
        'smtp_host'     => '',
        'smtp_port'     => 587,
        'smtp_security' => 'starttls',   // 'starttls' (587), 'tls' (465), 'none' (local relay only)
        'smtp_user'     => '',
        'smtp_password' => '',
    ],

    'admin' => [
        // The web admin panel is off while this is empty. Make the hash with:
        //   php bin/admin.php hash-password
        'password_hash' => '',
        'path'          => '/admin',
    ],

    // Storage per account (and per shared profile).
    'quota' => [
        'bytes'    => 5 * 1024 * 1024,
        'records'  => 20000,
        'profiles' => 100,
        'shares'   => 50,
    ],
];
