<?php
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 <https://opensource.org/licenses/apache-2.0>
 */
declare(strict_types=1);

namespace froq\encrypting;

use froq\encrypting\{EncryptingException, Generator, Hash};

/**
 * Uuid.
 *
 * @package froq\encrypting
 * @object  froq\encrypting\Uuid
 * @author  Kerem Güneş <k-gun@mail.com>
 * @since   3.0
 * @static
 */
final class Uuid
{
    /**
     * Generate.
     * @param  bool $dashed
     * @param  bool $guid
     * @return string
     */
    public static function generate(bool $dashed = true, bool $guid = false): string
    {
        // Random (UUID/v4 or GUID).
        $bytes = random_bytes(16);

        return self::formatBinary($bytes, $dashed, $guid);
    }

    /**
     * Generate hash.
     * @param  int  $hashLength
     * @param  bool $format
     * @return string
     * @throws froq\encrypting\EncryptingException
     * @since  4.3
     */
    public static function generateHash(int $hashLength = 32, bool $format = false): string
    {
        $hash = Hash::make(self::generate(false), $hashLength, [40, 16, 32, 64]);

        if ($format) {
            if ($hashLength != 32) {
                throw new EncryptingException('Format option for only 32-length hashes');
            }

            $hash = self::format($hash, true);
        }

        return $hash;
    }

    /**
     * Generate guid.
     * @param  bool $dashed
     * @return string
     * @since  4.8
     */
    public static function generateGuid(bool $dashed = true): string
    {
        return self::generate($dashed, true);
    }

    /**
     * Generate hash guid.
     * @param  int  $hashLength
     * @param  bool $format
     * @return string
     * @throws froq\encrypting\EncryptingException
     * @since  4.8
     */
    public static function generateHashGuid(int $hashLength = 32, bool $format = false): string
    {
        $hash = Hash::make(self::generateGuid(false), $hashLength, [40, 16, 32, 64]);

        if ($format) {
            if ($hashLength != 32) {
                throw new EncryptingException('Format option for only 32-length hashes');
            }

            $hash = self::format($hash, true);
        }

        return $hash;
    }

    /**
     * Generate with timestamp.
     * @param  bool $dashed
     * @param  bool $guid
     * @return string
     * @since  4.6, 4.9 Converted from generateUniq().
     */
    public static function generateWithTimestamp(bool $dashed = true, bool $guid = false): string
    {
        // Timestamp prefix.
        $prefix = dechex(time());

        // Binary of timestamp & 12-random bytes.
        $bytes = hex2bin($prefix) . random_bytes(12);

        return self::formatBinary($bytes, $dashed, $guid);
    }

    /**
     * Generate with timestamp hash.
     * @param  int  $hashLength
     * @param  bool $format
     * @return string
     * @throws froq\encrypting\EncryptingException
     * @since  4.6, 4.9 Converted from generateUniqHash().
     */
    public static function generateHashWithTimestamp(int $hashLength = 32, bool $format = false): string
    {
        $hash = Hash::make(self::generateWithTimestamp(false), $hashLength, [40, 16, 32, 64]);

        if ($format) {
            if ($hashLength != 32) {
                throw new EncryptingException('Format option for only 32-length hashes');
            }

            $hash = self::format($hash, true);
        }

        return $hash;
    }

    /**
     * Generate with namespace.
     * @param  string $namespace
     * @param  bool   $dashed
     * @param  bool   $guid
     * @return string
     * @since  4.9
     */
    public static function generateWithNamespace(string $namespace, bool $dashed = true, bool $guid = false): string
    {
        // Namespace prefix.
        $prefix = md5($namespace);
        $prefix = dechex(hexdec(substr($prefix, 0, 2)) | 1)
                              . substr($prefix, 2, 10);

        // Binary of namespace & 10-random bytes.
        $bytes = hex2bin($prefix) . random_bytes(10);

        return self::formatBinary($bytes, $dashed, $guid);
    }

    /**
     * Generate hash with namespace.
     * @param  string $namespace
     * @param  int    $hashLength
     * @param  bool   $format
     * @return string
     * @throws froq\encrypting\EncryptingException
     * @since  4.9
     */
    public static function generateHashWithNamespace(string $namespace, int $hashLength = 32, bool $format = false): string
    {
        $hash = Hash::make(self::generateWithNamespace($namespace, false), $hashLength, [40, 16, 32, 64]);

        if ($format) {
            if ($hashLength != 32) {
                throw new EncryptingException('Format option for only 32-length hashes');
            }

            $hash = self::format($hash, true);
        }

        return $hash;
    }

    /**
     * Generate serial.
     * @param  bool $dashed
     * @param  bool $dated
     * @param  bool $hexed
     * @return string
     * @since  4.0, 4.8 Replaced with generateSimple().
     */
    public static function generateSerial(bool $dashed = true, bool $hexed = false, bool $dated = false): string
    {
        $serial = Generator::generateId(32, ($hexed ? 16 : 10), $dated);

        return self::format($serial, $dashed);
    }

    /**
     * Generate random serial.
     * @param  bool $dashed
     * @param  bool $hexed
     * @return string
     * @since  4.0, 4.8 Replaced with generateDigit().
     */
    public static function generateRandomSerial(bool $dashed = true, bool $hexed = false): string
    {
        $serial = Generator::generateRandomId(32, ($hexed ? 16 : 10));

        return self::format($serial, $dashed);
    }

    /**
     * Format.
     * @param  string $in
     * @param  bool   $dashed
     * @return string
     */
    private static function format(string $in, bool $dashed): string
    {
        $out = vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split($in, 4));

        // Drop if false.
        $dashed || $out = str_replace('-', '', $out);

        return $out;
    }

    /**
     * Format binary.
     * @param  string $in
     * @param  bool   $dashed
     * @param  bool   $guid
     * @return string
     */
    private static function formatBinary(string $in, bool $dashed, bool $guid): string
    {
        // GUID doesn't use 4 (version) or 8, 9, A, B.
        if (!$guid) {
            $in[6] = chr(ord($in[6]) & 0x0f | 0x40);
            $in[8] = chr(ord($in[8]) & 0x3f | 0x80);
        }

        return self::format(bin2hex($in), $dashed);
    }
}
