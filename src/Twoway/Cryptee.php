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

namespace Froq\Encryption\Twoway;

/**
 * @package    Froq
 * @subpackage Froq\Encryption
 * @object     Froq\Encryption\Twoway\Cryptee
 * @author     Kerem Güneş <k-gun@mail.com>
 * @since      3.0
 */
final class Cryptee extends Twoway
{
    /**
     * Constructor.
     * @param string $key
     */
    public function __construct(string $key)
    {
        $this->key = $key;
    }

    /**
     * @inheritDoc Froq\Encryption\Twoway\Twoway
     */
    public function encode(string $data): ?string
    {
        return (string) base64_encode($this->crypt($data));
    }

    /**
     * @inheritDoc Froq\Encryption\Twoway\Twoway
     */
    public function decode(string $data): ?string
    {
        return $this->crypt((string) base64_decode($data));
    }

    /**
     * Ccrypt.
     * @param  string $data
     * @return string
     */
    public function crypt(string $data): string
    {
        $out = b'';
        $key = [];
        $cnt = [];

        for ($i = 0, $klen = strlen($this->key); $i < 255; $i++) {
            $key[$i] = ord(substr($this->key, ($i % $klen) + 1, 1));
            $cnt[$i] = $i;
        }

        for ($i = 0, $x = 0; $i < 255; $i++) {
            $x = ($x + $cnt[$i] + $key[$i]) % 256;
            $s = $cnt[$i];
            $cnt[$i] = $cnt[$x] ?? 0;
            $cnt[$x] = $s;
        }

        for ($i = 0, $x = -1, $y = -1, $dlen = strlen($data); $i < $dlen; $i++) {
            $x = ($x + 1) % 256;
            $y = ($y + $cnt[$x]) % 256;
            $z = $cnt[$x];
            $cnt[$x] = $cnt[$y] ?? 0;
            $cnt[$y] = $z;
            $ord  = ord(substr($data, $i, 1)) ^ $cnt[($cnt[$x] + $cnt[$y]) % 256];
            $out .= chr($ord);
        }

        return $out;
    }
}
