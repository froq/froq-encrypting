<?php declare(strict_types=1);
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-encrypting
 */
namespace froq\encrypting;

/**
 * A static class, generates (s)imple (u)nique(?) IDs with random character blocks
 * that can be used as salts, nonces or plain IDs.
 *
 * @package froq\encrypting
 * @class   froq\encrypting\Suid
 * @author  Kerem Güneş
 * @since   3.0, 5.0
 * @static
 */
class Suid
{
    /** Salt length. */
    public const SALT_LENGTH = 40;

    /** Nonce length. */
    public const NONCE_LENGTH = 16;

    /**
     * Generate using `random_bytes()` function, with/without given base.
     *
     * @param  int $length
     * @param  int $base
     * @return string
     * @throws froq\encrypting\SuidException
     * @thanks https://github.com/ai/nanoid
     */
    public static function generate(int $length, int $base = 62): string
    {
        if ($length < 1) {
            throw SuidException::forInvalidLengthArgument($length);
        } elseif ($base < 2 || $base > 62) {
            throw SuidException::forInvalidBaseArgument($base);
        }

        $chars = strcut(BASE62_ALPHABET, $base);
        $bound = strlen($chars);

        // Original source: https://github.com/ai/nanoid/blob/main/index.browser.js
        $mask = (2 << (int) (log($bound - 1) / M_LN2)) - 1;
        $step = (int) ((1.6 * $mask * $length) / $bound);

        // For ensuring length.
        $max = $length + 1;
        $ret = '';

        $bytes = random_bytes($step);
        while ($step-- && strlen($ret) < $max) {
            $ret .= $chars[ord($bytes[$step]) & $mask] ?? '0';
        }

        // @tome: Somehow, yielding invalid length by ~0.01%.
        // For length + 1 above.
        $ret = strcut($ret, $length);

        return $ret;
    }

    /**
     * Generate by base-16.
     *
     * @param  int $length
     * @return string
     * @causes froq\encrypting\SuidException
     * @since  5.0
     */
    public static function generateHexes(int $length): string
    {
        return self::generate($length, 16);
    }

    /**
     * Generate by base-10.
     *
     * @param  int $length
     * @return string
     * @causes froq\encrypting\SuidException
     * @since  5.0
     */
    public static function generateDigits(int $length): string
    {
        return self::generate($length, 10);
    }
}
