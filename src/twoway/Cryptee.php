<?php
/**
 * MIT License <https://opensource.org/licenses/mit>
 *
 * Copyright (c) 2015 Kerem Güneş
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is furnished
 * to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
declare(strict_types=1);

namespace froq\encryption\twoway;

use froq\encryption\EncryptionException;
use froq\encryption\twoway\Twoway;

/**
 * Cryptee.
 *
 * Original source https://github.com/k-gun/cryptee.
 *
 * @package froq\encryption\twoway
 * @object  froq\encryption\twoway\Cryptee
 * @author  Kerem Güneş <k-gun@mail.com>
 * @since   3.0
 */
final class Cryptee extends Twoway
{
    /**
     * Constructor.
     * @param  string $key
     * @throws froq\encryption\EncryptionException
     */
    public function __construct(string $key)
    {
        // Check key length.
        if (strlen($key) < 16) {
            throw new EncryptionException('Invalid key given, minimum key length is 16 (tip: use '.
                'Cryptee::generateKey() method to get a strong key)');
        }

        parent::__construct($key);
    }

    /**
     * @inheritDoc froq\encryption\twoway\Twoway
     */
    public function encode(string $data): ?string
    {
        return (string) base64_encode($this->crypt($data));
    }

    /**
     * @inheritDoc froq\encryption\twoway\Twoway
     */
    public function decode(string $data): ?string
    {
        return $this->crypt((string) base64_decode($data));
    }

    /**
     * Crypt.
     * @param  string $data
     * @return string
     */
    private function crypt(string $data): string
    {
        $key = [];
        $cnt = [];

        for ($i = 0, $klen = strlen($this->key); $i < 255; $i++) {
            $key[$i] = ord(substr($this->key, ($i % $klen) + 1, 1));
            $cnt[$i] = $i;
        }

        for ($i = 0, $a = 0; $i < 255; $i++) {
            $a = ($a + $cnt[$i] + $key[$i]) % 256;
            $t = $cnt[$i];

            $cnt[$i] = $cnt[$a] ?? 0;
            $cnt[$a] = $t;
        }

        $out = b'';

        for ($i = 0, $a = -1, $b = -1, $dlen = strlen($data); $i < $dlen; $i++) {
            $a = ($a + 1) % 256;
            $b = ($b + $cnt[$a]) % 256;
            $t = $cnt[$a];

            $cnt[$a] = $cnt[$b] ?? 0;
            $cnt[$b] = $t;

            $out .= chr(ord(substr($data, $i, 1)) ^ $cnt[($cnt[$a] + $cnt[$b]) % 256]);
        }

        return $out;
    }
}
