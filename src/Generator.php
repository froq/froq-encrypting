<?php
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-encrypting
 */
declare(strict_types=1);

namespace froq\encrypting;

/**
 * A static class, generates UUIDs, GUIDs, IDs, salts, nonces, tokens, serials,
 * and passwords.
 *
 * @package froq\encrypting
 * @object  froq\encrypting\Generator
 * @author  Kerem Güneş
 * @since   3.0
 * @static
 */
final class Generator
{
    /**
     * Generate a salt.
     *
     * @param  int $length
     * @param  int $base
     * @return string
     */
    public static function generateSalt(int $length = 40, int $base = 62): string
    {
        return Suid::generate($length, $base);
    }

    /**
     * Generate a nonce.
     *
     * @param  int $length
     * @param  int $base
     * @return string
     */
    public static function generateNonce(int $length = 16, int $base = 16): string
    {
        return Suid::generate($length, $base);
    }

    /**
     * Generate a token.
     *
     * @param  int $hashLength
     * @return string
     * @throws froq\encrypting\GeneratorException
     * @since  4.4
     */
    public static function generateToken(int $hashLength = 32): string
    {
        try {
            return Hash::make(uniqid(random_bytes(16), true), $hashLength, [32, 40, 16, 64]);
        } catch (HashException $e) {
            throw new GeneratorException($e->message, cause: $e);
        }
    }

    /**
     * Generate a UUID.
     *
     * @param  bool $dashed
     * @return string
     */
    public static function generateUuid(bool $dashed = true): string
    {
        return Uuid::generate($dashed);
    }

    /**
     * Generate a GUID.
     *
     * @param  bool $dashed
     * @return string
     * @since  4.0
     */
    public static function generateGuid(bool $dashed = true): string
    {
        return Uuid::generateGuid($dashed);
    }

    /**
     * Generate a serial.
     *
     * @param  int  $length
     * @param  bool $dated
     * @return string
     * @throws froq\encrypting\GeneratorException
     * @since  4.8
     */
    public static function generateSerial(int $length = 20, bool $dated = false): string
    {
        if ($length < 20) {
            throw new GeneratorException(
                'Argument $length must be minimun 20, %s given',
                $length
            );
        }

        return self::generateId($length, 10, $dated);
    }

    /**
     * Generate a random serial.
     *
     * @param  int $length
     * @return string
     * @throws froq\encrypting\GeneratorException
     * @since  4.8
     */
    public static function generateRandomSerial(int $length = 20): string
    {
        if ($length < 20) {
            throw new GeneratorException(
                'Argument $length must be minimun 20, %s given',
                $length
            );
        }

        return self::generateRandomId($length, 10);
    }

    /**
     * Generate a time/date based ID by given length.
     *
     * @param  int  $length
     * @param  int  $base
     * @param  bool $dated
     * @return string
     * @throws froq\encrypting\GeneratorException
     * @since  4.8
     */
    public static function generateId(int $length, int $base = 10, bool $dated = false): string
    {
        if ($length < 10) {
            throw new GeneratorException(
                'Argument $length must be minimun 10, %s given',
                $length
            );
        } elseif ($base < 10 || $base > 62) {
            throw new GeneratorException(
                'Argument $base must be between 10-62, %s given',
                $base
            );
        }

        /** @var DateTime */
        $now = udate('', 'UTC');

        // Use a date or time prefix (eg: 20121212.. or 1355270400..).
        $id = $dated ? $now->format('YmdHisu'): $now->format('Uu');

        if ($base == 10) {
            $ret = $id;
        } else {
            $ret = '';
            foreach (str_split($id, 10) as $i) {
                $ret .= Base::toBase($i, $base);
            }
        }

        // Pad if needed.
        while (strlen($ret) < $length) {
            $ret .= ($base == 10) ? random() : Base::toBase(random(), $base);
        }

        $ret = substr($ret, 0, $length);

        return $ret;
    }

    /**
     * Generate a short ID (16-length).
     *
     * @param  int  $base
     * @param  bool $dated
     * @return string
     * @since  4.8
     */
    public static function generateShortId(int $base = 10, bool $dated = false): string
    {
        return self::generateId(16, $base, $dated);
    }

    /**
     * Generate a long ID (32-length).
     *
     * @param  int  $base
     * @param  bool $dated
     * @return string
     * @since  4.8
     */
    public static function generateLongId(int $base = 10, bool $dated = false): string
    {
        return self::generateId(32, $base, $dated);
    }

    /**
     * Generate a serial ID (20-length digits).
     *
     * @param  bool $dated
     * @return string
     * @since  4.8
     */
    public static function generateSerialId(bool $dated = false): string
    {
        return self::generateId(20, 10, $dated);
    }

    /**
     * Generate a random ID by given length.
     *
     * @param  int $byteLength
     * @param  int $hashLength
     * @return string
     * @throws froq\encrypting\GeneratorException
     * @since  4.8
     */
    public static function generateRandomId(int $length, int $base = 10): string
    {
        if ($length < 4) {
            throw new GeneratorException(
                'Argument $length must be minimun 4, %s given',
                $length
            );
        } elseif ($base < 10 || $base > 62) {
            throw new GeneratorException(
                'Argument $base must be between 10-62, %s given',
                $base
            );
        }

        $chars    = Base::chars($base);
        $charsMax = strlen($chars) - 1;

        $ret = '';

        while (strlen($ret) < $length) {
            $ret .= $chars[random(0, $charsMax)];
        }

        return $ret;
    }

    /**
     * Generate a session ID.
     *
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
        } catch (\Error) {}

        // Let Suid to mimic it.
        $ret ??= Suid::generate(26, 36);

        $hash  && $ret = Hash::make($ret, $hashLength, [32, 40, 16]);
        $upper && $ret = strtoupper($ret);

        return $ret;
    }

    /**
     * Generate object ID (24-length hex like Mongo.ObjectId).
     *
     * @param  bool $counted
     * @return string
     * @since  4.0
     */
    public static function generateObjectId(bool $counted = true): string
    {
        static $counter = 0;

        $number = $counted ? ++$counter : random();
        $pack   = pack('N', time())     . substr(md5(gethostname()), 0, 3)
                . pack('n', getmypid()) . substr(pack('N', $number), 1, 3);

        $ret = '';

        // Convert bin pack to hex.
        for ($i = 0; $i < 12; $i++) {
            $ret .= sprintf('%02x', ord($pack[$i]));
        }

        return $ret;
    }

    /**
     * Generate a password.
     *
     * @param  int  $length
     * @param  bool $puncted
     * @return string
     */
    public static function generatePassword(int $length = 8, bool $puncted = false): string
    {
        return oneway\Password::generate($length, $puncted);
    }

    /**
     * Generate a one-time password.
     *
     * @param  string $key
     * @param  int    $length
     * @param  bool   $timed
     * @return string
     * @since  4.0
     */
    public static function generateOneTimePassword(string $key, int $length = 6, bool $timed = true): string
    {
        $number = $timed ? time() : random();
        $pack   = pack('NNC*', $number >> 32, $number & 0xffffffff);
        if (strlen($pack) < 8) {
            $pack = str_pad($pack, 8, chr(0), STR_PAD_LEFT);
        }

        $hash   = hash_hmac('sha256', $pack, $key);
        $offset = hexdec(substr($hash, -1)) * 2;
        $binary = hexdec(substr($hash, $offset, 8)) & 0x7fffffff;

        $ret = (string) fmod($binary, (10 ** $length));

        while (strlen($ret) < $length) {
            $ret .= random(0, 9);
        }

        return $ret;
    }
}
