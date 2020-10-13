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

use froq\encrypting\{Base, Hash, EncryptingException};

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
     * @param  bool $dash
     * @param  bool $guid
     * @return string
     */
    public static function generate(bool $dash = true, bool $guid = false): string
    {
        // Random (UUID/v4 or GUID).
        $bytes = random_bytes(16);

        return self::format($bytes, $dash, $guid);
    }

    /**
     * Generate uniq.
     * @param  bool $dash
     * @param  bool $guid
     * @return string
     * @since  4.6
     */
    public static function generateUniq(bool $dash = true, bool $guid = false): string
    {
        // Uniqid prefix (timestamp) with a random int to pad.
        $uniq = uniqid() . mt_rand(0, 9);

        // Binary of uniqid with 9-random bytes.
        $bytes = hex2bin($uniq) . random_bytes(9);

        return self::format($bytes, $dash, $guid);
    }

    /**
     * Generate hash.
     * @param  int $hashLength
     * @return string
     * @since  4.3
     */
    public static function generateHash(int $hashLength = 32): string
    {
        return self::hash(self::generate(), $hashLength);
    }

    /**
     * Generate uniq hash.
     * @param  int $hashLength
     * @return string
     * @since  4.6
     */
    public static function generateUniqHash(int $hashLength = 32): string
    {
        return self::hash(self::generateUniq(), $hashLength);
    }

    /**
     * Generate simple.
     * @return string
     * @since  4.0
     */
    public static function generateSimple(): string
    {
        // Simple serial.
        $date = getdate();
        $uniq = sscanf(uniqid('', true), '%8s%6s.%s');

        return sprintf('%.08s-%04x-%04x-%04x-%.6s%.6s',
            $uniq[0], $date['year'],
            ($date['mon'] . $date['mday']),
            ($date['minutes'] . $date['seconds']),
            $uniq[1], $uniq[2]
        );
    }

    /**
     * Generate digit.
     * @param  bool $rand
     * @return string
     * @since  4.0
     */
    public static function generateDigit(bool $rand = true): string
    {
        // All digit.
        if ($rand) {
            $digits = '';
            do {
                $digits .= mt_rand();
            } while (strlen($digits) < 32);
        } else {
            [$msec, $sec] = explode(' ', microtime());
            $digits = $sec . hrtime(true) . substr($msec, 2);
        }

        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split($digits, 4));
    }

    /**
     * Generate short.
     * @param  int $type
     * @return string A 16-length id.
     * @throws froq\encrypting\EncryptingException
     */
    public static function generateShort(int $type = 1): string
    {
        [$sec, $msec] = self::secs();

        if ($type == 1) { // Digits (0-9) @default.
            $out = $sec . $msec;
        } elseif ($type == 2) {  // Hexes (0-9, a-f).
            $out = Base::toBase($sec, 16) . Base::toBase($msec, 16);
        } elseif ($type == 3) {  // Chars (0-9, a-z).
            $out = Base::toBase($sec, 36) . Base::toBase($msec, 36);
        } elseif ($type == 4) {  // Chars (0-9, a-z, A-Z).
            $out = Base::toBase($sec, 62) . Base::toBase($msec, 62);
        } else {
            throw new EncryptingException('Invalid type value "%s" given, valids are: 1, 2, 3, 4',
                [$type]);
        }

        return self::pads($out, $type, 16);
    }

    /**
     * Generate long.
     * @param  int $type
     * @return string A 32-length id.
     * @throws froq\encrypting\EncryptingException
     * @since  3.6
     */
    public static function generateLong(int $type = 1): string
    {
        [$sec, $msec, $hsec] = self::secs();

        if ($type == 1) {        // Digits (0-9) @default.
            $out = $sec . $hsec . $msec;
        } elseif ($type == 2) {  // Hexes (0-9, a-f).
            $out = Base::toBase($sec, 16) . Base::toBase($hsec, 16) . Base::toBase($msec, 16);
        } elseif ($type == 3) {  // Chars (0-9, a-z).
            $out = Base::toBase($sec, 36) . Base::toBase($hsec, 36) . Base::toBase($msec, 36);
        } elseif ($type == 4) {  // Chars (0-9, a-z, A-Z).
            $out = Base::toBase($sec, 62) . Base::toBase($hsec, 62) . Base::toBase($msec, 62);
        } else {
            throw new EncryptingException('Invalid type value "%s" given, valids are: 1, 2, 3, 4',
                [$type]);
        }

        return self::pads($out, $type, 32);
    }

    /**
     * Secs.
     * @return array<int, int>
     */
    private static function secs(): array
    {
        $secs = sscanf(microtime(), '%d.%d %d');

        return [$secs[2], $secs[1], hrtime(true)];
    }

    /**
     * Pads.
     * @param  string $input
     * @param  int    $type
     * @param  int    $length
     * @return string
     */
    private static function pads(string $input, int $type, int $length): string
    {
        $pads = '';

        if (strlen($input) < $length) {
            if ($type == 1) {
                $pads = str_shuffle(Base::BASE_10_CHARS); // Numeric.
            } elseif ($type == 2) {
                $pads = str_shuffle(Base::BASE_16_CHARS); // Base 16.
            } elseif ($type == 3) {
                $pads = str_shuffle(Base::BASE_36_CHARS); // Base 36.
            } elseif ($type == 4) {
                $pads = str_shuffle(Base::BASE_62_CHARS); // Base 62.
            }
        }

        return substr($input . $pads, 0, $length);
    }

    /**
     * Hash.
     * @param  string $input
     * @param  int    $hashLength
     * @return string
     * @throws froq\encrypting\EncryptingException
     * @since  4.6
     */
    private static function hash(string $input, int $hashLength = 32): string
    {
        static $hashLengths = [40, 16, 32, 64];

        if (in_array($hashLength, $hashLengths, true)) {
            return Hash::make($input, $hashLength);
        }

        throw new EncryptingException('Invalid hash length value "%s" given, valids are: %s',
            [$hashLength, join(', ', $hashLengths)]);
    }

    /**
     * Format.
     * @param  string $bytes
     * @param  bool   $dash
     * @param  bool   $guid
     * @return string
     * @since  4.6
     */
    private static function format(string $bytes, bool $dash, bool $guid): string
    {
        // GUID doesn't use 4 (version) or 8, 9, A, or B.
        if (!$guid) {
            $bytes[6] = chr(ord($bytes[6]) & 0x0f | 0x40);
            $bytes[8] = chr(ord($bytes[8]) & 0x3f | 0x80);
        }

        $ret = vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($bytes), 4));

        if (!$dash) {
            $ret = str_replace('-', '', $ret);
        }

        return $ret;
    }
}
