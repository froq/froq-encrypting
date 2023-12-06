<?php declare(strict_types=1);
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-encrypting
 */
namespace froq\encrypting;

/**
 * A static class, generates UUIDs, GUIDs, IDs, salts, nonces, tokens, serials,
 * and passwords.
 *
 * @package froq\encrypting
 * @class   froq\encrypting\Generator
 * @author  Kerem Güneş
 * @since   3.0
 * @static
 */
class Generator
{
    /**
     * Generate a salt.
     *
     * @param  int $length
     * @param  int $base
     * @return string
     */
    public static function generateSalt(int $length = Suid::SALT_LENGTH, int $base = 62): string
    {
        try {
            return Suid::generate($length, $base);
        } catch (SuidException $e) {
            throw new GeneratorException($e);
        }
    }

    /**
     * Generate a nonce.
     *
     * @param  int $length
     * @param  int $base
     * @return string
     */
    public static function generateNonce(int $length = Suid::NONCE_LENGTH, int $base = 16): string
    {
        try {
            return Suid::generate($length, $base);
        } catch (SuidException $e) {
            throw new GeneratorException($e);
        }
    }

    /**
     * Generate a token.
     *
     * @param  int         $length
     * @param  string|null $prefix
     * @return string
     * @since  4.4
     */
    public static function generateToken(int $length = Token::LENGTH, string $prefix = null): string
    {
        try {
            return Token::generate($length, $prefix);
        } catch (TokenException $e) {
            throw new GeneratorException($e);
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
            throw GeneratorException::forMinimumLengthArgument(20, $length);
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
            throw GeneratorException::forMinimumLengthArgument(20, $length);
        }

        return self::generateRandomId($length, 10);
    }

    /**
     * Generate a time/date based ID.
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
            throw GeneratorException::forMinimumLengthArgument(10, $length);
        } elseif ($base < 10 || $base > 62) {
            throw GeneratorException::forInvalidBaseArgument($base);
        }

        /** @var DateTime */
        $now = udate('', 'UTC');

        // Use a date or time prefix (eg: 20121212.. or 1355270400..).
        $id = $dated ? $now->format('YmdHisu'): $now->format('Uu');

        if ($base === 10) {
            $ret = $id;
        } else {
            $ret = '';
            foreach (str_split($id, 10) as $i) {
                $ret .= Base::toBase($i, $base);
            }
        }

        // Pad if needed.
        while (strlen($ret) < $length) {
            $ret .= ($base === 10) ? random() : Base::toBase(random(), $base);
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
     * Generate a random ID.
     *
     * @param  int $length
     * @param  int $base
     * @return string
     * @throws froq\encrypting\GeneratorException
     * @since  4.8
     */
    public static function generateRandomId(int $length, int $base = 10): string
    {
        if ($length < 4) {
            throw GeneratorException::forMinimumLengthArgument(4, $length);
        } elseif ($base < 10 || $base > 62) {
            throw GeneratorException::forInvalidBaseArgument($base);
        }

        $chars = Base::chars($base);
        $bound = strlen($chars) - 1;

        $ret = '';

        while ($length--) {
            $ret .= $chars[random(0, $bound)];
        }

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
        $packed = pack('N', time())     . substr(md5(gethostname()), 0, 3)
                . pack('n', getmypid()) . substr(pack('N', $number), 1, 3);

        $ret = '';

        // Convert bin pack to hex.
        for ($i = 0; $i < 12; $i++) {
            $ret .= sprintf('%02x', ord($packed[$i]));
        }

        return $ret;
    }

    /**
     * Generate a password.
     *
     * @param  int  $length
     * @param  bool $puncted
     * @return string
     * @throws froq\encrypting\GeneratorException
     */
    public static function generatePassword(int $length = 16, bool $puncted = false): string
    {
        if ($length < 2) {
            throw GeneratorException::forMinimumLengthArgument(2, $length);
        }

        return random_string($length, $puncted);
    }

    /**
     * Generate a one-time password.
     *
     * @param  string $key
     * @param  int    $length
     * @return string
     * @since  4.0
     */
    public static function generateOneTimePassword(string $key, int $length = 6): string
    {
        $number = random();
        $packed = pack('NNC*', $number >> 32, $number & 0xffffffff);

        if (strlen($packed) < 8) {
            $packed = str_pad($packed, 8, chr(0), STR_PAD_LEFT);
        }

        $hashed = hash_hmac('sha256', $packed, $key);
        $offset = hexdec(substr($hashed, -1)) * 2;
        $binary = hexdec(substr($hashed, $offset, 8)) & 0x7fffffff;

        $ret = (string) fmod($binary, (10 ** $length));

        while (strlen($ret) < $length) {
            $ret .= random(0, 9);
        }

        return $ret;
    }
}
