<?php
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 <https://opensource.org/licenses/apache-2.0>
 */
declare(strict_types=1);

namespace froq\encrypting;

use froq\encrypting\EncryptingException;

/**
 * Base.
 *
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
                 BASE_10_CHARS  = '0123456789',
                 BASE_16_CHARS  = '0123456789abcdef',
                 BASE_36_CHARS  = '0123456789abcdefghijklmnopqrstuvwxyz',
                 BASE_62_CHARS  = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',
                 BASE_62N_CHARS = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                 // Misc.
                 BASE_32_CHARS  = '0123456789abcdefghjkmnpqrstvwxyz',
                 BASE_58_CHARS  = '123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ',
                 // Fun & alias.
                 FUN_CHARS      = 'fFuUnN',
                 HEX_CHARS      = self::BASE_16_CHARS,
                 ALL_CHARS      = self::BASE_62_CHARS;

    /**
     * Encode.
     * @param  string      $in
     * @param  string|null $chars @default=base62
     * @return string
     * @throws froq\encrypting\EncryptingException
     */
    public static function encode(string $in, string $chars = null): string
    {
        if ($in == '') return '';

        $chars = $chars ?? self::BASE_62_CHARS;
        if ($chars == '') {
            throw new EncryptingException('Characters must not be empty');
        }

        $base = strlen($chars);
        if ($base < 2 || $base > 256) {
            throw new EncryptingException('Characters length must be between 2-256, %s given', $base);
        }

        // Original source https://github.com/tuupola/base62.
        $tmp = array_map('ord', str_split($in));
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
     * @param  string      $in
     * @param  string|null $chars @default=base62
     * @return string
     * @throws froq\encrypting\EncryptingException
     */
    public static function decode(string $in, string $chars = null): string
    {
        if ($in == '') return '';

        $chars = $chars ?? self::BASE_62_CHARS;
        if ($chars == '') {
            throw new EncryptingException('Characters must not be empty');
        }

        $base = strlen($chars);
        if ($base < 2 || $base > 256) {
            throw new EncryptingException('Characters length must be between 2-256, %s given', $base);
        }

        if (strlen($in) !== strspn($in, $chars)) {
            preg_match('~[^'. preg_quote($chars, '~') .']+~', $in, $match);
            throw new EncryptingException("Invalid characters '%s' found in given input", $match[0]);
        }

        // Original source https://github.com/tuupola/base62.
        $tmp = array_map(fn($c) => strpos($chars, $c), str_split($in));
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
     * @param  array<int> $in
     * @param  int        $fromBase
     * @param  int        $toBase
     * @return array<int>
     */
    public static function convert(array $in, int $fromBase, int $toBase): array
    {
        // Original source http://codegolf.stackexchange.com/a/21672.
        $out = [];

        while ($count = count($in)) {
            $quotient  = [];
            $remainder = 0;

            $i = 0;
            while ($i < $count) {
                $accumulator = $in[$i++] + ($remainder * $fromBase);
                $digit       = ($accumulator / $toBase) | 0; // Int-div.
                $remainder   = $accumulator % $toBase;

                if ($quotient || $digit) {
                    $quotient[] = $digit;
                }
            }

            array_unshift($out, $remainder);

            $in = $quotient;
        }

        return $out;
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
            throw new EncryptingException('Argument $base must be between 2-62, %s given', $base);
        } elseif (!is_int($digits) && !is_string($digits)) {
            throw new EncryptingException('Argument $digits must be int|string, %s given', gettype($digits));
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
            throw new EncryptingException('Argument $base must be between 2-62, %s given', $base);
        } elseif (!is_int($digits) && !is_string($digits)) {
            throw new EncryptingException('Argument $digits must be int|string, %s given', gettype($digits));
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
