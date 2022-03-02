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
    public const BASE_10_CHARS  = '0123456789',
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
     * @param  string      $input
     * @param  string|null $chars @default=base62
     * @return string
     * @throws froq\encrypting\EncryptingException
     */
    public static function encode(string $input, string $chars = null): string
    {
        if ($input == '') {
            return '';
        }

        $chars ??= self::BASE_62_CHARS;
        if ($chars == '') {
            throw new EncryptingException('Characters cannot be empty');
        }

        $base = strlen($chars);
        if ($base < 2 || $base > 256) {
            throw new EncryptingException('Characters length must be between 2-256, %s given', $base);
        }

        // Original source https://github.com/tuupola/base62.
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
     * @param  string      $input
     * @param  string|null $chars @default=base62
     * @return string
     * @throws froq\encrypting\EncryptingException
     */
    public static function decode(string $input, string $chars = null): string
    {
        if ($input == '') {
            return '';
        }

        $chars ??= self::BASE_62_CHARS;
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

        // Original source https://github.com/tuupola/base62.
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
     * @param  array<int> $input
     * @param  int        $fromBase
     * @param  int        $toBase
     * @return array<int>
     */
    public static function convert(array $input, int $fromBase, int $toBase): array
    {
        // Original source http://codegolf.stackexchange.com/a/21672.
        $out = [];

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

            array_unshift($out, $remainder);

            $input = $quotient;
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
    public static function fromBase(int $base, int|string $digits): int
    {
        if ($base < 2 || $base > 62) {
            throw new EncryptingException('Argument $base must be between 2-62, %s given', $base);
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
    public static function toBase(int $base, int|string $digits): string
    {
        if ($base < 2 || $base > 62) {
            throw new EncryptingException('Argument $base must be between 2-62, %s given', $base);
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
