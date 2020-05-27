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

namespace froq\crypto;

use froq\crypto\{Base, CryptoException};

/**
 * Uuid.
 * @package froq\crypto
 * @object  froq\crypto\Uuid
 * @author  Kerem Güneş <k-gun@mail.com>
 * @since   3.0
 * @static
 */
final class Uuid
{
    /**
     * Generate.
     * @param  bool $guid
     * @return string
     */
    public static function generate(bool $guid = false): string
    {
        // Random (UUID/v4 or GUID).
        $rand = random_bytes(16);

        // GUID doesn't use 4 (version) or 8, 9, A, or B.
        if (!$guid) {
            $rand[6] = chr(ord($rand[6]) & 0x0f | 0x40);
            $rand[8] = chr(ord($rand[8]) & 0x3f | 0x80);
        }

        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($rand), 4));
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
     * @param  int $base
     * @return string A 16-length id.
     * @throws froq\crypto\CryptoException
     */
    public static function generateShort(int $base = 1): string
    {
        [$sec, $msec] = self::secs();

        if ($base == 1) { // Digits (0-9) @default.
            $out = $sec . $msec;
        } elseif ($base == 2) {  // Hexes (0-9, a-f).
            $out = Base::toBase($sec, 16) . Base::toBase($msec, 16);
        } elseif ($base == 3) {  // Chars (0-9, a-z).
            $out = Base::toBase($sec, 36) . Base::toBase($msec, 36);
        } elseif ($base == 4) {  // Chars (0-9, a-z, A-Z).
            $out = Base::toBase($sec, 62) . Base::toBase($msec, 62);
        } else {
            throw new CryptoException('Invalid base value "%s" given, valids are: 1, 2, 3, 4',
                [$base]);
        }

        return self::pads($base, 16, $out);
    }

    /**
     * Generate long.
     * @param  int $base
     * @return string A 32-length id.
     * @since  3.6
     * @throws froq\crypto\CryptoException
     */
    public static function generateLong(int $base = 1): string
    {
        [$sec, $msec, $hsec] = self::secs();

        if ($base == 1) {        // Digits (0-9) @default.
            $out = $sec . $hsec . $msec;
        } elseif ($base == 2) {  // Hexes (0-9, a-f).
            $out = Base::toBase($sec, 16) . Base::toBase($hsec, 16) . Base::toBase($msec, 16);
        } elseif ($base == 3) {  // Chars (0-9, a-z).
            $out = Base::toBase($sec, 36) . Base::toBase($hsec, 36) . Base::toBase($msec, 36);
        } elseif ($base == 4) {  // Chars (0-9, a-z, A-Z).
            $out = Base::toBase($sec, 62) . Base::toBase($hsec, 62) . Base::toBase($msec, 62);
        } else {
            throw new CryptoException('Invalid base value "%s" given, valids are: 1, 2, 3, 4',
                [$base]);
        }

        return self::pads($base, 32, $out);
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
     * @param  int    $type
     * @param  int    $length
     * @param  string $input
     * @return string
     */
    private static function pads(int $type, int $length, string $input): string
    {
        $pads = '';

        if (strlen($input) < $length) {
            if ($type == 1) {
                $pads = str_shuffle(Base::C10); // Numeric.
            } elseif ($type == 2) {
                $pads = str_shuffle(Base::C16); // Base 16.
            } elseif ($type == 3) {
                $pads = str_shuffle(Base::C36); // Base 36.
            } elseif ($type == 4) {
                $pads = str_shuffle(Base::C62); // Base 36.
            }
        }

        return substr($input . $pads, 0, $length);
    }
}
