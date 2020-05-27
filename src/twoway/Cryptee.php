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

namespace froq\crypto\twoway;

use froq\crypto\twoway\{Twoway, TwowayException};

/**
 * Cryptee.
 *
 * Original source https://github.com/k-gun/cryptee.
 *
 * @package froq\crypto\twoway
 * @object  froq\crypto\twoway\Cryptee
 * @author  Kerem Güneş <k-gun@mail.com>
 * @since   3.0
 */
final class Cryptee extends Twoway
{
    /**
     * Constructor.
     * @param  string $key
     * @throws froq\crypto\twoway\TwowayException
     */
    public function __construct(string $key)
    {
        // Check key length.
        if (strlen($key) < 16) {
            throw new TwowayException('Invalid key given, minimum key length is 16 (tip: use '.
                'Cryptee::generateKey() method to get a strong key)');
        }

        parent::__construct($key);
    }

    /**
     * @inheritDoc froq\crypto\twoway\Twoway
     */
    public function encode(string $data): ?string
    {
        return base64_encode($this->crypt($data));
    }

    /**
     * @inheritDoc froq\crypto\twoway\Twoway
     */
    public function decode(string $data): ?string
    {
        return $this->crypt(base64_decode($data));
    }

    /**
     * Crypt.
     * @param  string $data
     * @return string
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
