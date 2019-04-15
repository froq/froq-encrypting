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

namespace froq\encryption;

use froq\encryption\oneway\Password;

/**
 * Encryption.
 * @package froq\encryption
 * @object  froq\encryption\Encryption
 * @author  Kerem Güneş <k-gun@mail.com>
 * @since   1.0
 */
final class Encryption
{
    /**
     * Chars.
     * @const string
     */
    public const CHARS_16 = '0123456789abcdef',
                 CHARS_36 = '0123456789abcdefghijklmnopqrstuvwxyz',
                 CHARS_62 = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

    /**
     * Nonce algos.
     * @var array
     */
    private static $nonceAlgos = [8 => 'fnv1a32', 16 => 'fnv1a64', 32 => 'md5', 40 => 'sha1',
        64 => 'sha256', 128 => 'sha512'];

    /**
     * Generate salt.
     * @param  int|null $length
     * @param  bool     $translate
     * @return string
     * @since  3.0
     */
    public static function generateSalt(int $length = null, bool $translate = false): string
    {
        return Salt::generate($length, $translate);
    }

    /**
     * Generate uuid.
     * @param  int|null $type
     * @param  bool     $translate
     * @return string
     * @since  3.0
     */
    public static function generateUuid(int $type = null, bool $translate = false): string
    {
        return Uuid::generate($type, $translate);
    }

    /**
     * Generate short uuid.
     * @param  int|null $base
     * @return string
     * @since  3.0
     */
    public static function generateShortUuid(int $base = null): string
    {
        return Uuid::generateShort($base);
    }

    /**
     * Generate.
     * @param  int  $length
     * @param  bool $lettersOnly
     * @return string
     * @since  3.4
     */
    public static function generatePassword(int $length = 8, bool $lettersOnly = true): string
    {
        return Password::generate($length, $lettersOnly);
    }

    /**
     * Generate nonce.
     * @param  int $length
     * @return string
     * @throws froq\encryption\EncryptionException
     * @since  3.0
     */
    public static function generateNonce(int $length = 40): string
    {
        if (isset(self::$nonceAlgos[$length])) {
            return hash(self::$nonceAlgos[$length], random_bytes($length));
        }

        throw new EncryptionException(sprintf("Given length '{$length}' not implemented, only '%s' ".
            "are accepted", join(',', array_keys(self::$nonceAlgos))));
    }
}
