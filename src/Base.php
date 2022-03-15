<?php
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-encrypting
 */
declare(strict_types=1);

namespace froq\encrypting;

/**
 * Base.
 *
 * A static class, provides encode/decode methods for base conversions.
 *
 * @package froq\encrypting
 * @object  froq\encrypting\Base
 * @author  Kerem Güneş
 * @since   4.0
 * @static
 */
final class Base
{
    /**
     * Characters.
     * @const string
     */
    public const BASE10_CHARS  = '0123456789',
                 BASE16_CHARS  = '0123456789abcdef',
                 BASE36_CHARS  = '0123456789abcdefghijklmnopqrstuvwxyz',
                 BASE62_CHARS  = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',
                 // Native 62.
                 BASE62N_CHARS = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                 // Misc.
                 BASE32_CHARS  = '0123456789abcdefghjkmnpqrstvwxyz',
                 BASE58_CHARS  = '123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ',
                 BASE64_CHARS  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
                 // Fun.
                 FUN_CHARS     = 'fFuUnN',
                 // Alias.
                 HEX_CHARS     = self::BASE16_CHARS,
                 ALL_CHARS     = self::BASE62_CHARS;

    /**
     * Encode.
     *
     * @param  string $input
     * @param  string $chars
     * @return string
     * @throws froq\encrypting\EncryptingException
     * @thanks https://github.com/tuupola/base62
     */
    public static function encode(string $input, string $chars = self::BASE62_CHARS): string
    {
        if ($input == '') {
            return '';
        }

        if ($chars == '') {
            throw new EncryptingException('Characters cannot be empty');
        }

        $base = strlen($chars);
        if ($base < 2 || $base > 256) {
            throw new EncryptingException('Characters length must be between 2-256, %s given', $base);
        }

        $temp = array_map('ord', str_split($input));
        $zero = 0;
        while ($temp && $temp[0] === 0) {
            $zero++; array_shift($temp);
        }

        $temp = self::convert($temp, 256, $base);
        if ($zero) {
            $temp = array_merge(array_fill(0, $zero, 0), $temp);
        }

        return join(array_map(fn($i) => $chars[$i], $temp));
    }

    /**
     * Decode.
     *
     * @param  string $input
     * @param  string $chars
     * @return string
     * @throws froq\encrypting\EncryptingException
     * @thanks https://github.com/tuupola/base62
     */
    public static function decode(string $input, string $chars = self::BASE62_CHARS): string
    {
        if ($input == '') {
            return '';
        }

        if ($chars == '') {
            throw new EncryptingException('Characters cannot be empty');
        }

        $base = strlen($chars);
        if ($base < 2 || $base > 256) {
            throw new EncryptingException('Characters length must be between 2-256, %s given', $base);
        }

        if (strlen($input) !== strspn($input, $chars)) {
            preg_match('~[^'. preg_quote($chars, '~') .']+~', $input, $match);
            throw new EncryptingException('Invalid characters `%s` found in given input', $match[0]);
        }

        $temp = array_map(fn($c) => strpos($chars, $c), str_split($input));
        $zero = 0;
        while ($temp && $temp[0] === 0) {
            $zero++; array_shift($temp);
        }

        $temp = self::convert($temp, $base, 256);
        if ($zero) {
            $temp = array_merge(array_fill(0, $zero, 0), $temp);
        }

        return join(array_map('chr', $temp));
    }

    /**
     * Convert.
     *
     * @param  array<int> $input
     * @param  int        $fromBase
     * @param  int        $toBase
     * @return array<int>
     * @thanks http://codegolf.stackexchange.com/a/21672
     */
    public static function convert(array $input, int $fromBase, int $toBase): array
    {
        $ret = [];

        while ($count = count($input)) {
            $quotient  = [];
            $remainder = 0;

            $i = 0;
            while ($i < $count) {
                $accumulator = intval($input[$i++]) + ($remainder * $fromBase);
                $digit       = intdiv($accumulator, $toBase);
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
     *
     * @param  int|string $digits
     * @param  int        $base
     * @return int
     * @causes froq\encrypting\EncryptingException
     */
    public static function fromBase(int|string $digits, int $base): int
    {
        $chars  = self::chars($base);
        $digits = (string) $digits;

        $ret = strpos($chars, $digits[0]);

        for ($i = 1, $il = strlen($digits); $i < $il; $i++) {
            $ret = (int) (($base * $ret) + strpos($chars, $digits[$i]));
        }

        return $ret;
    }

    /**
     * To base.
     *
     * @param  int|string $digits
     * @param  int        $base
     * @return string
     * @causes froq\encrypting\EncryptingException
     */
    public static function toBase(int|string $digits, int $base): string
    {
        $chars  = self::chars($base);
        $digits = (int) $digits;

        $ret = '';

        do {
            $ret = $chars[$digits % $base] . $ret;
            $digits = (int) ($digits / $base);
        } while ($digits);

        return $ret;
    }

    /**
     * Chars.
     *
     * @param  int  $base
     * @param  bool $native
     * @return string
     * @throws froq\encrypting\EncryptingException
     */
    public static function chars(int $base, bool $native = false): string
    {
        if ($base < 2 || $base > 64) {
            throw new EncryptingException('Argument $base must be between 2-64, %s given', $base);
        }

        if ($base == 64) {
            return self::BASE64_CHARS;
        }

        return substr($native ? self::BASE62N_CHARS : self::BASE62_CHARS, 0, $base);
    }
}
