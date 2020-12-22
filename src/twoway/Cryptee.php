<?php
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 <https://opensource.org/licenses/apache-2.0>
 */
declare(strict_types=1);

namespace froq\encrypting\twoway;

use froq\encrypting\twoway\{Twoway, TwowayException};

/**
 * Cryptee.
 *
 * Represents a class entity which is able to twoway encrypting operations utilizing XOR way.
 * Original source https://github.com/k-gun/cryptee.
 *
 * @package froq\encrypting\twoway
 * @object  froq\encrypting\twoway\Cryptee
 * @author  Kerem Güneş <k-gun@mail.com>
 * @since   3.0
 */
final class Cryptee extends Twoway
{
    /**
     * Constructor.
     *
     * @param  string $key
     * @throws froq\encrypting\twoway\TwowayException
     */
    public function __construct(string $key)
    {
        // Check key length.
        if (strlen($key) < 16) {
            throw new TwowayException('Invalid key length `%s`, minimum key length is 16 [tip: use '
                . 'Cryptee::generateKey() method to get a strong key]', strlen($key));
        }

        parent::__construct($key);
    }

    /**
     * @inheritDoc froq\encrypting\twoway\Twoway
     */
    public function encode(string $data, bool $raw = false): string|null
    {
        $out = $this->crypt($data);

        return !$raw ? base64_encode($out) : $out;
    }

    /**
     * @inheritDoc froq\encrypting\twoway\Twoway
     */
    public function decode(string $data, bool $raw = false): string|null
    {
        $data = !$raw ? base64_decode($data, true) : $data;

        return $this->crypt($data);
    }

    /**
     * Crypt.
     *
     * @param  string $data
     * @return string
     * @internal
     */
    private function crypt(string $data): string
    {
        $top = 256;
        $key = $cnt = [];

        for ($i = 0, $len = strlen($this->key); $i < $top; $i++) {
            $key[$i] = ord(substr($this->key, ($i % $len) + 1, 1));
            $cnt[$i] = $i;
        }

        for ($i = 0, $a = 0; $i < $top; $i++) {
            $a = ($a + $cnt[$i] + $key[$i]) % $top;
            $t = $cnt[$i];

            $cnt[$i] = $cnt[$a] ?? 0;
            $cnt[$a] = $t;
        }

        $out = b'';

        for ($i = 0, $a = -1, $b = -1, $len = strlen($data); $i < $len; $i++) {
            $a = ($a + 1) % $top;
            $b = ($b + $cnt[$a]) % $top;
            $t = $cnt[$a];

            $cnt[$a] = $cnt[$b] ?? 0;
            $cnt[$b] = $t;

            $out .= chr(ord(substr($data, $i, 1)) ^ $cnt[($cnt[$a] + $cnt[$b]) % $top]);
        }

        return $out;
    }
}
