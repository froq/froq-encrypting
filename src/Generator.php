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

use froq\encrypting\{EncryptingException, Base, Hash, Salt, Uuid};
use froq\encrypting\oneway\Password;
use Error;

/**
 * Generator.
 * @package froq\encrypting
 * @object  froq\encrypting\Generator
 * @author  Kerem Güneş <k-gun@mail.com>
 * @since   3.0
 * @static
 */
final class Generator
{
    /**
     * Generate salt.
     * @param  int $length
     * @param  int $bitsPerChar
     * @return string
     */
    public static function generateSalt(int $length = 40, int $bitsPerChar = 6): string
    {
        return Salt::generate($length, $bitsPerChar);
    }

    /**
     * Generate nonce.
     * @param  int $length
     * @param  int $bitsPerChar
     * @return string
     */
    public static function generateNonce(int $length = 16, int $bitsPerChar = 4): string
    {
        return Salt::generate($length, $bitsPerChar);
    }

    /**
     * Generate uuid.
     * @param  bool $dashed
     * @return string
     */
    public static function generateUuid(bool $dashed = true): string
    {
        return Uuid::generate($dashed);
    }

    /**
     * Generate guid.
     * @param  bool $dashed
     * @return string
     * @since  4.0
     */
    public static function generateGuid(bool $dashed = true): string
    {
        return Uuid::generateGuid($dashed);
    }

    /**
     * Generate uniq uuid.
     * @param  bool $dashed
     * @return string
     * @since  4.6
     */
    public static function generateUniqUuid(bool $dashed = true): string
    {
        return Uuid::generateUniq($dashed);
    }

    /**
     * Generate token.
     * @param  int $hashLength
     * @return string
     * @since  4.4
     */
    public static function generateToken(int $hashLength = 32): string
    {
        return Hash::make(uniqid(random_bytes(16), true), $hashLength, [40, 16, 32, 64]);
    }

    /**
     * Generate serial.
     * @param  int  $length
     * @param  bool $dated
     * @return string
     * @since  4.8
     */
    public static function generateSerial(int $length = 20, bool $dated = false): string
    {
        if ($length < 20) {
            throw new EncryptingException('Argument $length must be minimun 20, %s given',
                [$length]);
        }

        return self::generateId($length, 10, $dated);
    }

    /**
     * Generate random serial.
     * @param  int $length
     * @return string
     * @since  4.8
     */
    public static function generateRandomSerial(int $length = 20): string
    {
        if ($length < 20) {
            throw new EncryptingException('Argument $length must be minimun 20, %s given',
                [$length]);
        }

        return self::generateRandomId($length, 10);
    }

    /**
     * Generate id.
     * @param  int  $length
     * @param  int  $base
     * @param  bool $dated
     * @return string
     * @throws froq\encrypting\EncryptingException
     * @since  4.8
     */
    public static function generateId(int $length, int $base = 10, bool $dated = false): string
    {
        if ($length < 10) {
            throw new EncryptingException('Argument $length must be minimun 10, %s given',
                [$length]);
        } elseif ($base < 10 || $base > 62) {
            throw new EncryptingException('Argument $base must be between 10-62, %s given',
                [$base]);
        }

        // Now (date/time object).
        $now = udate('', 'UTC');

        // Use a date prefix or time (eg: 20121229.. or 1401873..).
        $id = $dated ? $now->format('YmdHisu') : $now->format('Uu');

        if ($base == 10) {
            $ret = $id;
        } else {
            $ret = '';
            foreach (str_split($id, 10) as $i) {
                $ret .= Base::toBase($base, $i);
            }
        }

        // Pad or crop if needed.
        if (strlen($ret) < $length) {
            $chars = substr(Base::ALL_CHARS, 0, $base);
            $charsLength = strlen($chars);

            while (strlen($ret) < $length) {
                $ret .= $chars[mt_rand(0, $charsLength - 1)];
            }
        } else {
            $ret = substr($ret, 0, $length);
        }

        return $ret;
    }

    /**
     * Generate short id.
     * @param  int  $base
     * @param  bool $dated
     * @return string A 16-length id.
     * @since  4.8 Moved from Uuid.generateShort().
     */
    public static function generateShortId(int $base = 10, bool $dated = false): string
    {
        return self::generateId(16, $base, $dated);
    }

    /**
     * Generate long id.
     * @param  int  $base
     * @param  bool $dated
     * @return string A 32-length id.
     * @since  4.8 Moved from Uuid.generateLong().
     */
    public static function generateLongId(int $base = 10, bool $dated = false): string
    {
        return self::generateId(32, $base, $dated);
    }

    /**
     * Generate serial id.
     * @param  bool $dated
     * @return string A 20-length id (digits).
     * @since  4.8
     */
    public static function generateSerialId(bool $dated = false): string
    {
        return self::generateId(20, 10, $dated);
    }

    /**
     * Generate random id.
     * @param  int $byteLength
     * @param  int $hashLength
     * @return string
     * @since  4.8
     */
    public static function generateRandomId(int $length, int $base = 10): string
    {
        if ($length < 4) {
            throw new EncryptingException('Argument $length must be minimun 4, %s given',
                [$length]);
        } elseif ($base < 10 || $base > 62) {
            throw new EncryptingException('Argument $base must be between 10-62, %s given',
                [$base]);
        }

        $chars = substr(Base::ALL_CHARS, 0, $base);
        $charsLength = strlen($chars);

        $ret = '';

        while (strlen($ret) < $length) {
            $ret .= $chars[mt_rand(0, $charsLength - 1)];
        }

        return $ret;
    }

    /**
     * Generate session id.
     * @param  array|null $options
     * @return string
     * @since  4.7
     */
    public static function generateSessionId(array $options = null): string
    {
        // Extract options with defaults.
        extract(($options ?? []) + ['hash' => false, 'hashLength' => 32, 'upper' => false]);

        // Session may be not loaded.
        try {
            $ret = session_create_id() ?: null;
        } catch (Error $e) {}

        // Let Salt to mimic it.
        $ret ??= Salt::generate(26, 5);

        $hash && $ret = Hash::make($ret, $hashLength, [40, 16, 32]);
        $upper && $ret = strtoupper($ret);

        return $ret;
    }

    /**
     * Generate object id.
     * @param  bool   $counted
     * @return string A 24-length hex like Mongo.ObjectId.
     * @since  4.0
     */
    public static function generateObjectId(bool $counted = true): string
    {
        static $counter = 0;

        $number = $counted ? $counter++ : mt_rand();
        $pack   = pack('N', time()) . substr(md5(gethostname()), 0, 3)
                . pack('n', getmypid()) . substr(pack('N', $number), 1, 3);

        $ret = '';

        // Convert bin pack to hex.
        for ($i = 0; $i < 12; $i++) {
            $ret .= sprintf('%02x', ord($pack[$i]));
        }

        return $ret;
    }

    /**
     * Generate password.
     * @param  int  $length
     * @param  bool $puncted
     * @return string
     */
    public static function generatePassword(int $length = 8, bool $puncted = false): string
    {
        return Password::generate($length, $puncted);
    }

    /**
     * Generate one time password.
     * @param  string $key
     * @param  int    $length
     * @return string
     * @since  4.0
     */
    public static function generateOneTimePassword(string $key, int $length = 6, bool $timed = true): string
    {
        $number = $timed ? time() : mt_rand();
        $pack   = pack('NNC*', $number >> 32, $number & 0xffffffff);
        if (strlen($pack) < 8) {
            $pack = str_pad($pack, 8, chr(0), STR_PAD_LEFT);
        }

        $hash   = hash_hmac('sha256', $pack, $key);
        $offset = hexdec(substr($hash, -1)) * 2;
        $binary = hexdec(substr($hash, $offset, 8)) & 0x7fffffff;

        $ret = strval($binary % pow(10, $length));
        while (strlen($ret) < $length) {
            $ret .= mt_rand(0, 9);
        }

        return $ret;
    }
}
