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

use froq\encrypting\{Generator, Hash};

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
     * @param  bool $dashed
     * @param  bool $guid
     * @return string
     */
    public static function generate(bool $dashed = true, bool $guid = false): string
    {
        // Random (UUID/v4 or GUID).
        $bytes = random_bytes(16);

        return self::formatBinary($bytes, $dashed, $guid);
    }

    /**
     * Generate hash.
     * @param  int $hashLength
     * @return string
     * @since  4.3
     */
    public static function generateHash(int $hashLength = 32): string
    {
        return Hash::make(self::generate(false), $hashLength, [40, 16, 32, 64]);
    }

    /**
     * Generate uniq.
     * @param  bool $dashed
     * @param  bool $guid
     * @return string
     * @since  4.6
     */
    public static function generateUniq(bool $dashed = true, bool $guid = false): string
    {
        // Uniqid prefix with a random int (for fixing 14-length).
        $uniq = uniqid() . mt_rand(0, 9);

        // Binary of uniqid with 9-random bytes.
        $bytes = hex2bin($uniq) . random_bytes(9);

        return self::formatBinary($bytes, $dashed, $guid);
    }

    /**
     * Generate uniq hash.
     * @param  int $hashLength
     * @return string
     * @since  4.6
     */
    public static function generateUniqHash(int $hashLength = 32): string
    {
        return Hash::make(self::generateUniq(false), $hashLength, [40, 16, 32, 64]);
    }

    /**
     * Generate guid.
     * @param  bool $dashed
     * @return string
     * @since  4.8
     */
    public static function generateGuid(bool $dashed = true): string
    {
        return self::generate($dashed, true);
    }

    /**
     * Generate guid hash.
     * @param  int $hashLength
     * @return string
     * @since  4.8
     */
    public static function generateGuidHash(int $hashLength = 32): string
    {
        return Hash::make(self::generateGuid(false), $hashLength, [40, 16, 32, 64]);
    }

    /**
     * Generate serial.
     * @param  bool $dashed
     * @param  bool $dated
     * @param  bool $hexed
     * @return string
     * @since  4.0, 4.8 Replaced with generateSimple().
     */
    public static function generateSerial(bool $dashed = true, bool $hexed = false, bool $dated = false): string
    {
        $serial = Generator::generateId(32, ($hexed ? 16 : 10), $dated);

        return self::format($serial, $dashed);
    }

    /**
     * Generate random serial.
     * @param  bool $dashed
     * @param  bool $hexed
     * @return string
     * @since  4.0, 4.8 Replaced with generateDigit().
     */
    public static function generateRandomSerial(bool $dashed = true, bool $hexed = false): string
    {
        $serial = Generator::generateRandomId(32, ($hexed ? 16 : 10));

        return self::format($serial, $dashed);
    }

    /**
     * Format.
     * @param  string $input
     * @param  bool   $dashed
     * @return string
     */
    private static function format(string $input, bool $dashed): string
    {
        $ret = vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split($input, 4));

        if (!$dashed) {
            $ret = str_replace('-', '', $ret);
        }

        return $ret;
    }

    /**
     * Format binary.
     * @param  string $input
     * @param  bool   $dashed
     * @param  bool   $guid
     * @return string
     */
    private static function formatBinary(string $input, bool $dashed, bool $guid): string
    {
        // GUID doesn't use 4 (version) or 8, 9, A, B.
        if (!$guid) {
            $input[6] = chr(ord($input[6]) & 0x0f | 0x40);
            $input[8] = chr(ord($input[8]) & 0x3f | 0x80);
        }

        return self::format(bin2hex($input), $dashed);
    }
}
