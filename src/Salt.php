<?php
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 <https://opensource.org/licenses/apache-2.0>
 */
declare(strict_types=1);

namespace froq\encrypting;

use froq\encrypting\{Base, EncryptingException};

/**
 * Salt.
 *
 * @package froq\encrypting
 * @object  froq\encrypting\Salt
 * @author  Kerem Güneş <k-gun@mail.com>
 * @since   3.0
 * @static
 */
final class Salt
{
    /**
     * Length.
     * @const int
     */
    public const LENGTH = 128;

    /**
     * Bits-per-char.
     * @const int
     */
    public const BITS_PER_CHAR = 6;

    /**
     * Generate.
     * @param  int|null $length      Output length.
     * @param  int|null $bitsPerChar 4=base16 (hex), 5=base36, 6=base62.
     * @return string
     * @throws froq\encrypting\EncryptingException.
     */
    public static function generate(int $length = null, int $bitsPerChar = null): string
    {
        $len = $length ?? self::LENGTH;
        $bpc = $bitsPerChar ?? self::BITS_PER_CHAR;

        if ($len < 2) {
            throw new EncryptingException("Invalid length value '%s', length must be greater than 1", $len);
        } elseif ($bpc < 4 || $bpc > 6) {
            throw new EncryptingException("Invalid bits-per-char value '%s', valids are: 4, 5, 6", $bpc);
        }

        $bytes = random_bytes((int) ceil($len * $bpc / 8));

        $chars = ($bpc == 6) ? Base::BASE_62_CHARS : (
            ($bpc == 5) ? Base::BASE_36_CHARS : Base::BASE_16_CHARS);
        $charsLength = strlen($chars);

        // Original source https://github.com/php/php-src/blob/master/ext/session/session.c#L267,#L326.
        $p = 0; $q = strlen($bytes);
        $w = 0; $have = 0; $mask = (1 << $bpc) - 1;

        $out = '';

        while ($len--) {
            if ($have < $bpc) {
                if ($p < $q) {
                    $byte = ord($bytes[$p++]);
                    $w |= ($byte << $have);
                    $have += 8;
                } else {
                    break;
                }
            }

            $i = $w & $mask;

            // Fix up index picking a random index.
            if ($i > $charsLength - 1) {
                $i = mt_rand(0, $charsLength - 1);
            }

            $out .= $chars[$i];

            $w >>= $bpc;
            $have -= $bpc;
        }

        return $out;
    }
}
