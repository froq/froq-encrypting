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

use froq\encrypting\{Hash, Salt, Uuid};
use froq\encrypting\oneway\Password;

/**
 * Generator.
 * @package froq\encrypting
 * @object  froq\encrypting\Generator
 * @author  Kerem Güneş <k-gun@mail.com>
 * @since   1.0
 * @static
 */
final class Generator
{
    /**
     * Generate salt.
     * @param  int|null $length
     * @param  int|null $bitsPerChar
     * @return string
     * @since  3.0
     */
    public static function generateSalt(int $length = null, int $bitsPerChar = null): string
    {
        return Salt::generate($length, $bitsPerChar);
    }

    /**
     * Generate uuid.
     * @param  bool $guid
     * @return string
     * @since  3.0
     */
    public static function generateUuid(bool $guid = false): string
    {
        return Uuid::generate($guid);
    }

    /**
     * Generate guid.
     * @return string
     * @since  4.0
     */
    public static function generateGuid(): string
    {
        return Uuid::generate(true);
    }

    /**
     * Generate simple uuid.
     * @return string
     * @since  4.0
     */
    public static function generateSimpleUuid(): string
    {
        return Uuid::generateSimple();
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
     * Generate long uuid.
     * @param  int|null $base
     * @return string
     * @since  3.6
     */
    public static function generateLongUuid(int $base = null): string
    {
        return Uuid::generateLong($base);
    }

    /**
     * Generate.
     * @param  int  $length
     * @param  bool $lettersOnly
     * @return string
     * @since  3.0
     */
    public static function generatePassword(int $length = 8, bool $lettersOnly = true): string
    {
        return Password::generate($length, $lettersOnly);
    }

    /**
     * Generate one time password.
     * @param  string $key
     * @param  int    $length
     * @return string A time based OTP (One-Time-Password).
     * @since  4.0
     */
    public static function generateOneTimePassword(string $key, int $length = 8): string
    {
        $time = time();
        $data = pack('NNC*', $time >> 32, $time & 0xffffffff);
        if (strlen($data) < 8) {
            $data = str_pad($data, 8, chr(0), STR_PAD_LEFT);
        }

        $hash   = hash_hmac('sha256', $data, $key);
        $offset = hexdec(substr($hash, -1)) * 2;
        $binary = hexdec(substr($hash, $offset, 8)) & 0x7fffffff;

        $ret = (string) ($binary % pow(10, $length));
        if (strlen($ret) < $length) {
            $ret = str_pad($ret, $length, '0', STR_PAD_LEFT);
        }

        return $ret;
    }

    /**
     * Generate nonce.
     * @param  int $length
     * @return string
     * @since  3.0
     */
    public static function generateNonce(int $length = 32): string
    {
        return bin2hex(random_bytes($length / 2));
    }

    /**
     * Generate nonce hash.
     * @param  int $length
     * @return string
     * @since  4.0
     */
    public static function generateNonceHash(int $length = 32): string
    {
        return Hash::make(self::generateNonce($length), $length);
    }

    /**
     * Generate serial.
     * @return string A 20-length big number.
     * @since  3.7
     */
    public static function generateSerial(): string
    {
        return self::generateId();
    }

    /**
     * Generate serial hash.
     * @param  int $length
     * @return string A given-length hex string.
     * @since  3.7
     */
    public static function generateSerialHash(int $length = 32): string
    {
        return Hash::make(self::generateId(), $length);
    }

    /**
     * Generate id.
     * @since  4.0
     * @return string
     */
    public static function generateId(): string
    {
        $tmp = explode(' ', microtime());

        return $tmp[1] . substr($tmp[0], 2, 6) . random_int(1000, 9999);
    }

    /**
     * Generate uniq id.
     * @param  bool $simple
     * @since  4.0
     * @return string
     */
    public static function generateUniqId(bool $simple = true): string
    {
        $ret = uniqid('', true);

        if ($simple) {
            return strstr($ret, '.', true);
        }

        return substr(vsprintf('%14s%\'06x', explode('.', $ret)), 0, 20);
    }

    /**
     * Generate object id.
     * @param  bool   $count
     * @return string A 24-length hex like Mongo.ObjectId.
     * @since  4.0
     */
    public static function generateObjectId(bool $count = true): string
    {
        static $counter = 0;

        $binary = pack('N', time()) . substr(md5(gethostname()), 0, 3)
                . pack('n', getmypid()) . substr(pack('N', $count ? $counter++ : mt_rand()), 1, 3);

        $ret = '';

        // Convert to hex.
        for ($i = 0; $i < 12; $i++) {
            $ret .= sprintf('%02x', ord($binary[$i]));
        }

        return $ret;
    }
}
