<?php
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-encrypting
 */
declare(strict_types=1);

namespace froq\encrypting;

use froq\encrypting\{Base, EncryptingException};

/**
 * Suid.
 *
 * Represents a static class which is able to generate simple unique IDs with random character blocks these
 * can be used as salts, nonces or IDs.
 *
 * @package froq\encrypting
 * @object  froq\encrypting\Suid
 * @author  Kerem Güneş
 * @since   3.0, 5.0 Replaced with Salt & refactored with "nanoid" style.
 * @static
 */
final class Suid
{
    /**
     * Generate using random_bytes() utility, with/without given base.
     *
     * @param  int $length
     * @param  int $base
     * @return string
     * @throws froq\encrypting\EncryptingException
     */
    public static function generate(int $length, int $base = 62): string
    {
        if ($length < 1) {
            throw new EncryptingException('Invalid length value `%s`, length must be greater than 1', $length);
        } elseif ($base < 2 || $base > 62) {
            throw new EncryptingException('Argument $base must be between 2-62, %s given', $base);
        }

        $chars = substr(Base::BASE_62_CHARS, 0, $base);
        $charsLength = strlen($chars);

        // Original source: https://github.com/ai/nanoid/blob/main/index.browser.js
        $mask = (2 << log($charsLength - 1) / M_LN2) - 1;
        $step = (1.6 * $mask * $length / $charsLength) | 0;

        $ret = '';

        $bytes = random_bytes($step);
        while ($step-- && strlen($ret) < $length) {
            $ret .= $chars[ord($bytes[$step]) & $mask] ?? '';
        }

        return $ret;
    }

    /**
     * Generate in base-16.
     *
     * @param  int $length
     * @return string
     * @since  5.0
     * @causes froq\encrypting\EncryptingException
     */
    public static function generateHexes(int $length): string
    {
        return self::generate($length, 16);
    }

    /**
     * Generate in base-10.
     *
     * @param  int $length
     * @return string
     * @since  5.0
     * @causes froq\encrypting\EncryptingException
     */
    public static function generateDigits(int $length): string
    {
        return self::generate($length, 10);
    }
}
