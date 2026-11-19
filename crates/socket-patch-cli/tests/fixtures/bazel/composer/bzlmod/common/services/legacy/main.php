<?php
// Prints OUT: PRISTINE <id> until the package is patched. The one argument
// is Composer's autoload.php.
require $argv[1];
echo 'OUT: ' . \SocketFixture\Upstream::STATUS . "\n";
