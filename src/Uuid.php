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

namespace froq\encrypting;

use froq\encrypting\{Base, EncryptingException};

/**
 * Uuid.
 * @package froq\encrypting
 * @object  froq\encrypting\Uuid
 * @author  Kerem Güneş <k-gun@mail.com>
 * @since   3.0
 * @static
 */
final class Uuid
{
    /**
     * Generate.
     * @param  bool $simple
     * @param  bool $guid
     * @return string
     */
    public static function generate(bool $simple = false, bool $guid = false): string
    {
        $out = '';

        // Random (UUID/v4 or GUID).
        if (!$simple) {
            $rand = random_bytes(16);

            if (!$guid) {
                // GUID doesn't use 4 (version) or 8, 9, A, or B.
                $rand[6] = chr(ord($rand[6]) & 0x0f | 0x40);
                $rand[8] = chr(ord($rand[8]) & 0x3f | 0x80);
            }

            $out = vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($rand), 4));
        }
        // Simple serial.
        else {
            $date = getdate();
            $uniq = preg_split('~([a-f0-9]{8})([a-f0-9]{6})~', uniqid('', true), -1,
                PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
            $rand = bin2hex(random_bytes(3));

            $out = sprintf('%08s-%04x-%04x-%04x-%6s%6s', $uniq[0], $date['year'],
                ($date['mon'] . $date['mday']), ($date['minutes'] . $date['seconds']), $uniq[1], $rand);
        }

        return $out;
    }

    /**
     * Generate simple.
     * @return string
     * @since  4.0
     */
    public static function generateSimple(): string
    {
        return self::generate(true);
    }

    /**
     * Generate short.
     * @param  int|null $base
     * @return string   A 12-length id.
     * @throws froq\encrypting\EncryptingException
     */
    public static function generateShort(int $base = null): string
    {
        [$time, $mtime] = self::times();

        $base = $base ?? 10;
        if ($base == 10) {
            $out = ''. $time . $mtime;
            $out = self::pad(1, 12, $out);
        } elseif ($base == 16) {
            $out = dechex($time) . dechex($mtime);
            $out = self::pad(2, 12, $out);
        } elseif ($base == 36) {
            $out = base_convert($time, 10, 36) . base_convert($mtime, 10, 36);
            $out = self::pad(3, 12, $out);
        } else {
            throw new EncryptingException(
                'Invalid base value "%s" given, valids are "10, 16, 36"', [$base]
            );
        }

        return $out;
    }

    /**
     * Generate long.
     * @param  int|null $base
     * @return string   A 22-length id.
     * @since  3.6
     * @throws froq\encrypting\EncryptingException
     */
    public static function generateLong(int $base = null): string
    {
        [$time, $mtime] = self::times();

        $base = $base ?? 10;
        if ($base == 10) {
            $out = ''. $time . $mtime;
            $out = self::pad(1, 22, $out);
        } elseif ($base == 16) {
            $out = dechex($time) . dechex($mtime);
            $out = self::pad(2, 22, $out);
        } elseif ($base == 36) {
            $out = base_convert($time, 10, 36) . base_convert($mtime, 10, 36);
            $out = self::pad(3, 22, $out);
        } else {
            throw new EncryptingException(
                'Invalid base value "%s" given, valids are "10, 16, 36"', [$base]
            );
        }

        return $out;
    }

    /**
     * Times.
     * @return array<int, int>
     */
    private static function times(): array
    {
        $tmp = explode(' ', microtime());

        return [(int) $tmp[1], (int) substr($tmp[0], 2, 6)];
    }

    /**
     * Pad.
     * @param  int    $type
     * @param  int    $length
     * @param  string $input
     * @return string
     */
    private static function pad(int $type, int $length, string $input): string
    {
        $chars = '';

        if (strlen($input) < $length) {
            if ($type == 1) {
                $chars = str_shuffle(Base::C10); // Numeric.
            } elseif ($type == 2) {
                $chars = str_shuffle(Base::C16); // Base 16.
            } elseif ($type == 3) {
                $chars = str_shuffle(Base::C36); // Base 36.
            }
        }

        return substr($input . $chars, 0, $length);
    }
}
