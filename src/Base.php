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

use froq\encrypting\EncryptingException;

/**
 * Base.
 * @package froq\encrypting
 * @object  froq\encrypting\Base
 * @author  Kerem Güneş <k-gun@mail.com>
 * @since   4.0
 * @static
 */
final class Base
{
    /**
     * Characters.
     * @const string
     */
    public const C10 = '0123456789',
                 C16 = '0123456789abcdef',
                 C36 = '0123456789abcdefghijklmnopqrstuvwxyz',
                 C62 = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',
                 // Misc.
                 C32 = '0123456789abcdefghjkmnpqrstvwxyz',
                 C58 = '123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ',
                 FUN = 'fFuUnN',
                 // Alias.
                 HEX = self::C16,
                 ALL = self::C62;

    /**
     * Encode.
     * @param  string      $input
     * @param  string|null $characters Default is Base62.
     * @return string
     * @throws froq\encrypting\EncryptingException
     */
    public static function encode(string $input, string $characters = null): string
    {
        if ($input == '') return '';

        $characters = $characters ?? self::C62;
        if ($characters == '') {
            throw new EncryptingException('Characters must not be empty');
        }

        $base = strlen($characters);
        if ($base < 2 || $base > 255) {
            throw new EncryptingException('Characters base (length) must be min 2 and max 255, '.
                '%s given', [$base]);
        }

        // Original source https://github.com/tuupola/base62.
        $tmp = array_map('ord', str_split($input));
        $tmp = self::convert($tmp, 256, $base);

        return join('', array_map(fn($i) => $characters[$i], $tmp));
    }

    /**
     * Decode.
     * @param  string      $input
     * @param  string|null $characters Default is Base62.
     * @return string
     * @throws froq\encrypting\EncryptingException
     */
    public static function decode(string $input, string $characters = null): string
    {
        if ($input == '') return '';

        $characters = $characters ?? self::C62;
        if ($characters == '') {
            throw new EncryptingException('Characters must not be empty');
        }

        $base = strlen($characters);
        if ($base < 2 || $base > 255) {
            throw new EncryptingException('Characters base (length) must be min 2 and max 255, '.
                '%s given', [$base]);
        }

        if (strlen($input) !== strspn($input, $characters)) {
            preg_match('~[^'. preg_quote($characters, '~') .']+~', $input, $match);
            throw new EncryptingException('Invalid characters "%s" found in given input',
                [$match[0]]);
        }

        // Original source https://github.com/tuupola/base62.
        $tmp = array_map(fn($c) => strpos($characters, $c), str_split($input));
        $tmp = self::convert($tmp, $base, 256);

        return join('', array_map('chr', $tmp));
    }

    /**
     * Convert.
     * @param  array<int> $input
     * @param  int        $fromBase
     * @param  int        $toBase
     * @return array<int>
     */
    public static function convert(array $input, int $fromBase, int $toBase): array
    {
        // Original source http://codegolf.stackexchange.com/a/21672.
        $ret = [];

        while ($count = count($input)) {
            $quotient  = [];
            $remainder = 0;

            $i = 0;
            while ($i < $count) {
                $accumulator = $input[$i++] + ($remainder * $fromBase);
                $digit       = ($accumulator / $toBase) | 0; // Int-div.
                $remainder   = $accumulator % $toBase;

                if ($quotient || $digit) {
                    $quotient[] = $digit;
                }
            }

            array_unshift($ret, $remainder);

            $input = $quotient;
        }

        return $ret;
    }

    /**
     * From base.
     * @param  string $digits
     * @param  int    $base
     * @return int
     */
    public static function fromBase(string $digits, int $base = 62): int
    {
        if ($base < 2 || $base > 62) {
            throw new EncryptingException('Base must be between 2 and 62, %s given', [$base]);
        }

        $ret = strpos(self::ALL, $digits[0]) | 0;

        for ($i = 1, $il = strlen($digits); $i < $il; $i++) {
            $ret = ($base * $ret) + strpos(self::ALL, $digits[$i]);
        }

        return $ret;
    }

    /**
     * To base.
     * @param  int $digits
     * @param  int $base
     * @return string
     */
    public static function toBase(int $digits, int $base = 62): string
    {
        if ($base < 2 || $base > 62) {
            throw new EncryptingException('Base must be between 2 and 62, %s given', [$base]);
        }

        $ret = '';

        do {
            $ret = self::ALL[$digits % $base] . $ret;
            $digits = ($digits / $base) | 0;
        } while ($digits);

        return $ret;
    }
}
