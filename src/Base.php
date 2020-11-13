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
    public const // From util.sugars-constant.
                 BASE_10_CHARS  = BASE_10_CHARS,
                 BASE_16_CHARS  = BASE_16_CHARS,
                 BASE_36_CHARS  = BASE_36_CHARS,
                 BASE_62_CHARS  = BASE_62_CHARS,
                 BASE_62N_CHARS = BASE_62N_CHARS,
                 // Misc.
                 BASE_32_CHARS  = '0123456789abcdefghjkmnpqrstvwxyz',
                 BASE_58_CHARS  = '123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ',
                 // Fun & alias.
                 FUN_CHARS      = 'fFuUnN',
                 HEX_CHARS      = self::BASE_16_CHARS,
                 ALL_CHARS      = self::BASE_62_CHARS;

    /**
     * Encode.
     * @param  string      $input
     * @param  string|null $chars @default=base62
     * @return string
     * @throws froq\encrypting\EncryptingException
     */
    public static function encode(string $input, string $chars = null): string
    {
        if ($input == '') return '';

        $chars = $chars ?? self::BASE_62_CHARS;
        if ($chars == '') {
            throw new EncryptingException('Characters must not be empty');
        }

        $base = strlen($chars);
        if ($base < 2 || $base > 256) {
            throw new EncryptingException('Characters base (length) must be min 2 and max 256, '.
                '%s given', [$base]);
        }

        // Original source https://github.com/tuupola/base62.
        $tmp = array_map('ord', str_split($input));
        $zrs = 0;
        while ($tmp && $tmp[0] === 0) {
            $zrs++; array_shift($tmp);
        }

        $tmp = self::convert($tmp, 256, $base);
        if ($zrs) {
            $tmp = array_merge(array_fill(0, $zrs, 0), $tmp);
        }

        return join('', array_map(fn($i) => $chars[$i], $tmp));
    }

    /**
     * Decode.
     * @param  string      $input
     * @param  string|null $chars @default=base62
     * @return string
     * @throws froq\encrypting\EncryptingException
     */
    public static function decode(string $input, string $chars = null): string
    {
        if ($input == '') return '';

        $chars = $chars ?? self::BASE_62_CHARS;
        if ($chars == '') {
            throw new EncryptingException('Characters must not be empty');
        }

        $base = strlen($chars);
        if ($base < 2 || $base > 256) {
            throw new EncryptingException('Characters base (length) must be min 2 and max 256, '.
                '%s given', [$base]);
        }

        if (strlen($input) !== strspn($input, $chars)) {
            preg_match('~[^'. preg_quote($chars, '~') .']+~', $input, $match);
            throw new EncryptingException('Invalid characters "%s" found in given input',
                [$match[0]]);
        }

        // Original source https://github.com/tuupola/base62.
        $tmp = array_map(fn($c) => strpos($chars, $c), str_split($input));
        $zrs = 0;
        while ($tmp && $tmp[0] === 0) {
            $zrs++; array_shift($tmp);
        }

        $tmp = self::convert($tmp, $base, 256);
        if ($zrs) {
            $tmp = array_merge(array_fill(0, $zrs, 0), $tmp);
        }

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
     * @param  int        $base
     * @param  int|string $digits
     * @return int
     * @throws froq\encrypting\EncryptingException
     */
    public static function fromBase(int $base, $digits): int
    {
        if ($base < 2 || $base > 62) {
            throw new EncryptingException('Argument $base must be between 2-62, %s given',
                [$base]);
        } elseif (!is_int($digits) && !is_string($digits)) {
            throw new EncryptingException('Argument $digits must be int|string, %s given',
                [gettype($digits)]);
        }

        $digits = strval($digits);

        $ret = strpos(self::BASE_62_CHARS, $digits[0]) | 0;

        for ($i = 1, $il = strlen($digits); $i < $il; $i++) {
            $ret = (($base * $ret) + strpos(self::BASE_62_CHARS, $digits[$i])) | 0;
        }

        return $ret;
    }

    /**
     * To base.
     * @param  int        $base
     * @param  int|string $digits
     * @return string
     * @throws froq\encrypting\EncryptingException
     */
    public static function toBase(int $base, $digits): string
    {
        if ($base < 2 || $base > 62) {
            throw new EncryptingException('Argument $base must be between 2-62, %s given',
                [$base]);
        } elseif (!is_int($digits) && !is_string($digits)) {
            throw new EncryptingException('Argument $digits must be int|string, %s given',
                [gettype($digits)]);
        }

        $digits = intval($digits);

        $ret = '';

        do {
            $ret = self::BASE_62_CHARS[$digits % $base] . $ret;
            $digits = ($digits / $base) | 0;
        } while ($digits);

        return $ret;
    }
}
