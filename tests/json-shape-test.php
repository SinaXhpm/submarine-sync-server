<?php
// Util::jsonShapeOk (the guard against JSON hash-flooding) and RateLimit's bucket key.
//   php tests/json-shape-test.php          (no server or database needed)
declare(strict_types=1);

require __DIR__ . '/../src/lib/Util.php';

use Submarine\Lib\Util;

$fail = 0;
$ok = function (string $label, bool $cond, string $info = '') use (&$fail): void {
    if (!$cond) { $fail++; }
    echo ($cond ? 'PASS ' : 'FAIL ') . $label . ($info !== '' ? ": $info" : '') . "\n";
};
$time = function (callable $f): array {
    $t = microtime(true);
    $r = $f();
    return [$r, microtime(true) - $t];
};

// A body like a real push: 5000 records, 8 keys each, a 700-hex blob.
$records = [];
for ($i = 0; $i < 5000; $i++) {
    $records[] = ['uuid' => bin2hex(random_bytes(16)), 'entity_type' => 'servers', 'updated_at' => '000001760000000:00001:abcd', 'deleted' => false, 'blob' => bin2hex(random_bytes(350)), 'rev' => $i, 'edited_by' => 'me@example.com', 'x' => 1];
}
$legit = json_encode(['profile' => 'abc', 'since' => '', 'records' => $records]);
[$r, $t] = $time(fn () => Util::jsonShapeOk($legit));
$ok('a real 5000-record push passes (' . round(strlen($legit) / 1048576, 1) . ' MB)', $r === true, sprintf('%.3f s', $t));
$ok('and is looked at in well under a second', $t < 1.0);

// 100,000 tiny records: many objects, few keys each.
$tiny = json_encode(['records' => array_fill(0, 100000, ['a' => 1, 'b' => 2, 'c' => 3])]);
[$r, $t] = $time(fn () => Util::jsonShapeOk($tiny));
$ok('100,000 small objects pass', $r === true, sprintf('%.3f s for %d KB', $t, strlen($tiny) / 1024));

// One object with 107,000 keys: the shape of the attack (these keys don't even collide).
$flood = '{' . implode(',', array_map(fn ($n) => '"k' . $n . '":1', range(0, 107000))) . '}';
[$r, $t] = $time(fn () => Util::jsonShapeOk($flood));
$ok('an object with 107,000 keys is refused', $r === false);
$ok('and refused at once (early exit)', $t < 0.2, sprintf('%.4f s', $t));

// The same inside a record, inside the usual wrapper.
$nested = '{"profile":"p","records":[{"uuid":"u","blob":"b",' . implode(',', array_map(fn ($n) => '"k' . $n . '":1', range(0, 5000))) . '}]}';
$ok('too many keys in a nested object is refused too', Util::jsonShapeOk($nested . str_repeat(' ', 20000)) === false);

// Exactly at the limit passes; one over does not.
$at = '{' . implode(',', array_map(fn ($n) => '"k' . $n . '":1', range(1, Util::MAX_OBJECT_KEYS))) . '}' . str_repeat(' ', 20000);
$over = '{' . implode(',', array_map(fn ($n) => '"k' . $n . '":1', range(1, Util::MAX_OBJECT_KEYS + 1))) . '}' . str_repeat(' ', 20000);
$ok('1000 keys are fine', Util::jsonShapeOk($at) === true);
$ok('1001 are not', Util::jsonShapeOk($over) === false);

// Padding with extra empty objects does not hide it.
$padded = '[' . str_repeat('{},', 50000) . $flood . ']';
$ok('padding with empty objects does not hide a flood', Util::jsonShapeOk($padded) === false);

// Strings that look like structure.
$tricky = json_encode(['records' => [['name' => 'a"b":1,"c":2', 'note' => '{"x":1,"y":2,"z":3}', 'blob' => str_repeat('"\\\\', 10)]]]) . str_repeat(' ', 20000);
$ok('quotes, colons and braces inside strings are not keys', Util::jsonShapeOk($tricky) === true);
$escaped = '{"a\\"b":1,"c\\\\":2,' . implode(',', array_map(fn ($n) => '"k' . $n . '":1', range(0, 1200))) . '}' . str_repeat(' ', 20000);
$ok('escaped quotes in keys do not throw the count off', Util::jsonShapeOk($escaped) === false);

// Depth.
$deep = str_repeat('[', 100) . str_repeat(']', 100) . str_repeat(' ', 20000);
$ok('a body 100 levels deep is refused', Util::jsonShapeOk($deep) === false);
$fine = str_repeat('[', 10) . str_repeat(']', 10) . str_repeat(' ', 20000);
$ok('ten levels are fine', Util::jsonShapeOk($fine) === true);

// Not JSON: left to json_decode.
$ok('an unterminated string is left to json_decode', Util::jsonShapeOk('{"a":"' . str_repeat('x', 20000)) === true);
$ok('plain text is left to json_decode', Util::jsonShapeOk(str_repeat('hello ', 5000)) === true);
$ok('a small body skips the pass', Util::jsonShapeOk('{"a":1}') === true);
// 15 KB, under the threshold: skipped even with many keys (it can't hold enough to matter).
$small = '{' . implode(',', array_map(fn ($n) => '"k' . $n . '":1', range(0, 1500))) . '}';
$ok('under 16 KB the pass is skipped (1501 keys, ' . strlen($small) . ' bytes)', strlen($small) < 16384 && Util::jsonShapeOk($small) === true);

// RateLimit::key (private): through reflection.
require __DIR__ . '/../src/lib/RateLimit.php';
$rl = (new ReflectionClass(Submarine\Lib\RateLimit::class))->newInstanceWithoutConstructor();
$key = new ReflectionMethod($rl, 'key');
$key->setAccessible(true);
$short = 'login:email:alice@example.com';
$ok('a short bucket is stored as it is', $key->invoke($rl, $short) === $short);
$long = 'signup:email:' . str_repeat('a', 160) . '@example.com'; // 13 + 172 chars
$k1 = $key->invoke($rl, $long);
$k2 = $key->invoke($rl, $long . 'x');
$ok('a long bucket fits the 191-character column', strlen($k1) <= 191, (string) strlen($k1));
$ok('two long names that start the same do not share a bucket', $k1 !== $k2);
$ok('the same long name always gets the same bucket', $k1 === $key->invoke($rl, $long));
$ok('the longest email the API takes fits, with the longest prefix', strlen($key->invoke($rl, 'loginlink:email:' . str_repeat('b', 191))) <= 191);

echo $fail ? "\n$fail FAILED\n" : "\nALL PASS\n";
exit($fail ? 1 : 0);
