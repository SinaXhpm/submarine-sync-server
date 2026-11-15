<?php
// Submarine sync server — the only file the web server runs. Everything else
// lives outside this folder (src/, bin/, config.php) and is never served.

declare(strict_types=1);

define('SUBMARINE_API', true);
require dirname(__DIR__) . '/src/api.php';
