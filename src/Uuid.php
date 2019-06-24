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

namespace froq\encryption;

/**
 * Uuid.
 * @package froq\encryption
 * @object  froq\encryption\Uuid
 * @author  Kerem Güneş <k-gun@mail.com>
 * @since   3.0
 */
final /* static */ class Uuid
{
    /**
     * Generate.
     * @param  bool $simple
     * @param  bool $translate
     * @return string
     * @throws froq\encryption\EncryptionException
     */
    public static function generate(bool $simple = true, bool $translate = false): string
    {
        $out = '';

        if ($simple) { // simple serial
            $date = getdate();
            $uniq = preg_split('~([a-f0-9]{8})([a-f0-9]{6})~', uniqid('', true), -1,
                PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
            $rand = bin2hex(random_bytes(3));

            $out = sprintf('%08s-%04x-%04x-%04x-%6s%6s', $uniq[0], $date['year'],
                ($date['mon'] . $date['mday']), ($date['minutes'] . $date['seconds']), $uniq[1], $rand);
        } else { // random (UUID/v4)
            $rand = random_bytes(16);
            $rand[6] = chr(ord($rand[6]) & 0x0f | 0x40);
            $rand[8] = chr(ord($rand[8]) & 0x3f | 0x80);

            $out = vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($rand), 4));
        }

        // remove dashes
        if ($translate) {
            $out = str_replace('-', '', $out);
        }

        return $out;
    }

    /**
     * Generate short.
     * @param  int|null $base
     * @return string
     */
    public static function generateShort(int $base = null): string
    {
        $time = time();

        if ($base == null) { // number, length=13
            $out = ''. $time . random_int(100, 999);
        } elseif ($base == 16) { // string, length=12
            $out = dechex($time) . dechex(random_int(100, 999));
            $out = str_pad($out, 12, self::rand('hex'));
        } elseif ($base == 36) { // string, length=11
            $out = base_convert($time, 10, 36) . base_convert(random_int(100, 999), 10, 36)
                 . base_convert(random_int(100, 999), 10, 36);
            $out = str_pad($out, 11, self::rand('char'));
        } else {
            throw new EncryptionException("Given base '{$base}' not implemented, only '16,36' are accepted");
        }

        return $out;
    }

    /**
     * Generate long.
     * @param  int|null $base
     * @return string
     * @since  3.6
     */
    public static function generateLong(int $base = null): string
    {
        [$time, $microtime] = (function () {
            $tmp = explode(' ', microtime());
            return [(int) $tmp[1], (int) substr($tmp[0], 2, 6)];
        })();

        if ($base == null) { // (big)number, length=20
            $out = ''. $time . $microtime . random_int(1000, 9999);
        } elseif ($base == 16) { // string, length=18
            $out = dechex($time) . dechex($microtime) . dechex(random_int(10000, 99999));
            $out = str_pad($out, 18, self::rand('hex'));
        } elseif ($base == 36) { // string, length=16
            $out = base_convert($time, 10, 36) . base_convert($microtime, 10, 36)
                 . base_convert(random_int(1000, 9999), 10, 36) . base_convert(random_int(1000, 9999), 10, 36);
            $out = str_pad($out, 16, self::rand('char'));
        }

        return $out;
    }

    /**
     * Rand.
     * @param  string $what
     * @return string
     */
    private static function rand(string $what): string
    {
        if ($what == 'hex') return str_shuffle(Encryption::CHARS_16)[0];
        if ($what == 'char') return str_shuffle(encryption::CHARS_36)[0];
    }
}
