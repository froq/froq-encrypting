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

use froq\encrypting\{EncryptingException, Hash, Salt, Uuid};
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
     * @param  bool $dash
     * @param  bool $guid
     * @return string
     * @since  3.0
     */
    public static function generateUuid(bool $dash = false, bool $guid = false): string
    {
        return Uuid::generate($dash, $guid);
    }

    /**
     * Generate uuid hash.
     * @param  int $hashLength
     * @return string
     * @since  4.3
     */
    public static function generateUuidHash(int $hashLength = 32): string
    {
        return Uuid::generateHash($hashLength);
    }

    /**
     * Generate uniq uuid.
     * @param  bool $dash
     * @param  bool $guid
     * @return string
     * @since  4.6
     */
    public static function generateUniqUuid(bool $dash = false, bool $guid = false): string
    {
        return Uuid::generateUniq($dash, $guid);
    }

    /**
     * Generate uniq uuid hash.
     * @param  int $hashLength
     * @return string
     * @since  4.6
     */
    public static function generateUniqUuidHash(int $hashLength = 32): string
    {
        return Uuid::generateUniqHash($hashLength);
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
     * Generate digit uuid.
     * @param  bool $rand
     * @return string
     * @since  4.0
     */
    public static function generateDigitUuid(bool $rand = true): string
    {
        return Uuid::generateDigit($rand);
    }

    /**
     * Generate short uuid.
     * @param  int $type
     * @return string
     * @since  3.0
     */
    public static function generateShortUuid(int $type = 1): string
    {
        return Uuid::generateShort($type);
    }

    /**
     * Generate long uuid.
     * @param  int $type
     * @return string
     * @since  3.6
     */
    public static function generateLongUuid(int $type = 1): string
    {
        return Uuid::generateLong($type);
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
     * Generate nonce.
     * @param  int $length
     * @param  int $bitsPerChar
     * @return string
     * @since  3.0
     */
    public static function generateNonce(int $length = 40, int $bitsPerChar = 6): string
    {
        return Salt::generate($length, $bitsPerChar);
    }

    /**
     * Generate nonce hash.
     * @param  int $length
     * @param  int $bitsPerChar
     * @param  int $hashLength
     * @return string
     * @since  4.0
     */
    public static function generateNonceHash(int $length = 40, int $bitsPerChar = 6, int $hashLength = 40): string
    {
        return Hash::make(Salt::generate($length, $bitsPerChar), $hashLength);
    }

    /**
     * Generate token.
     * @param  int $hashLength
     * @return string
     * @throws froq\encrypting\EncryptingException
     * @since  4.4
     */
    public static function generateToken(int $hashLength = 40): string
    {
        static $hashLengths = [40, 16, 32, 64, 128];

        if (in_array($hashLength, $hashLengths, true)) { // For a safe token hash.
            return Hash::make(uniqid(random_bytes(16), true), $hashLength);
        }

        throw new EncryptingException('Invalid hash length value "%s" given, valids are: %s',
            [$hashLength, join(', ', $hashLengths)]);
    }

    /**
     * Generate serial.
     * @aliasOf generateId().
     * @since   3.7
     */
    public static function generateSerial(bool $useDate = false): string
    {
        return self::generateId($useDate);
    }

    /**
     * Generate serial hash.
     * @param  bool $useDate
     * @param  int  $hashLength
     * @return string 16|N-length hex.
     * @since  3.7
     */
    public static function generateSerialHash(bool $useDate = false, int $hashLength = 16): string
    {
        return Hash::make(self::generateSerial($useDate), $hashLength);
    }

    /**
     * Generate id.
     * @param  bool $useDate
     * @return string A 20|24-length digits.
     * @since  4.0
     */
    public static function generateId(bool $useDate = false): string
    {
        $mic = explode(' ', microtime());
        $ret = !$useDate ? $mic[1] : date('YmdHis');

        return $ret . substr($mic[0], 2, 6) . mt_rand(1000, 9999);
    }

    /**
     * Generate uniq id.
     * @param  bool $useSimple
     * @return string A 20|14-length hex.
     * @since  4.0
     */
    public static function generateUniqId(bool $useSimple = false): string
    {
        $ret = uniqid('', true);

        if (!$useSimple) {
            $ret = vsprintf('%14s%\'06x', explode('.', $ret));
            return substr($ret, 0, 20);
        }

        return strstr($ret, '.', true);
    }

    /**
     * Generate random id.
     * @param  int $byteLength
     * @param  int $hashLength
     * @return string N-length hex.
     * @since  4.3
     */
    public static function generateRandomId(int $byteLength = 16, int $hashLength = 16): string
    {
        return Hash::make(random_bytes($byteLength), $hashLength);
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

    /**
     * Generate password.
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
    public static function generateOneTimePassword(string $key, int $length = 6): string
    {
        $time = time();
        $data = pack('NNC*', $time >> 32, $time & 0xffffffff);
        if (strlen($data) < 8) {
            $data = str_pad($data, 8, chr(0), STR_PAD_LEFT);
        }

        $hash   = hash_hmac('sha256', $data, $key);
        $offset = hexdec(substr($hash, -1)) * 2;
        $binary = hexdec(substr($hash, $offset, 8)) & 0x7fffffff;

        $ret = strval($binary % pow(10, $length));
        if (strlen($ret) < $length) {
            $ret = str_pad($ret, $length, '0', STR_PAD_LEFT);
        }

        return $ret;
    }
}
