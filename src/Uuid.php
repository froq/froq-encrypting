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
 * Represents a static class which is able to generate UUIDs (v4) from random bytes and optionally with
 * timestamp/namespaces or GUIDs from random bytes and hashes of these with/without given lengths, also
 * to generate time-based or random serials.
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
     * Generate a UUID with random 16-length bytes.
     *
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
     * Generate a hash from a generated UUID.
     *
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
            ($hashLength == 32) || throw new EncryptingException('Format option for only 32-length hashes');

            $hash = self::format($hash, true);
        }

        return $hash;
    }

    /**
     * Generate a GUID with random 16-length bytes.
     *
     * @param  bool $dashed
     * @return string
     * @since  4.8
     */
    public static function generateGuid(bool $dashed = true): string
    {
        return self::generate($dashed, true);
    }

    /**
     * Generate a GUID hash from a generated GUID.
     *
     * @param  int  $hashLength
     * @param  bool $format
     * @return string
     * @throws froq\encrypting\EncryptingException
     * @since  4.8
     */
    public static function generateGuidHash(int $hashLength = 32, bool $format = false): string
    {
        $hash = Hash::make(self::generateGuid(false), $hashLength, [40, 16, 32, 64]);

        if ($format) {
            ($hashLength == 32) || throw new EncryptingException('Format option for only 32-length hashes');

            $hash = self::format($hash, true);
        }

        return $hash;
    }

    /**
     * Generate a UUID with timestamp and random 12-length bytes.
     *
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
     * Generate a timestamp-ed UUID hash.
     *
     * @param  int  $hashLength
     * @param  bool $format
     * @return string
     * @throws froq\encrypting\EncryptingException
     * @since  4.6, 4.9 Converted from generateUniqHash().
     */
    public static function generateWithTimestampHash(int $hashLength = 32, bool $format = false): string
    {
        $hash = Hash::make(self::generateWithTimestamp(false), $hashLength, [40, 16, 32, 64]);

        if ($format) {
            ($hashLength == 32) || throw new EncryptingException('Format option for only 32-length hashes');

            $hash = self::format($hash, true);
        }

        return $hash;
    }

    /**
     * Generate a UUID with a namespace and random 10-length bytes.
     *
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
     * Generate a namespace-d UUID hash.
     *
     * @param  string $namespace
     * @param  int    $hashLength
     * @param  bool   $format
     * @return string
     * @throws froq\encrypting\EncryptingException
     * @since  4.9
     */
    public static function generateWithNamespaceHash(string $namespace, int $hashLength = 32, bool $format = false): string
    {
        $hash = Hash::make(self::generateWithNamespace($namespace, false), $hashLength, [40, 16, 32, 64]);

        if ($format) {
            ($hashLength == 32) || throw new EncryptingException('Format option for only 32-length hashes');

            $hash = self::format($hash, true);
        }

        return $hash;
    }

    /**
     * Generate a 32-length serial.
     *
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
     * Generate a 32-length random serial.
     *
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
     * Check whether given UUID is is valid.
     *
     * @param  string $uuid
     * @param  bool   $dashed
     * @return bool
     * @since  5.0
     */
    public static function valid(string $uuid, bool $dashed = true): bool
    {
        return $dashed ? preg_match('~^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$~', $in)
                       : preg_match('~^[a-f0-9]{32}$~', $in);
    }

    /**
     * Check whether given UUID hash is is valid.
     *
     * @param  string $hash
     * @return bool
     * @since  5.0
     */
    public static function validHash(string $hash): bool
    {
        return preg_match('~^[a-f0-9]{32}$~', $in);
    }

    /**
     * Format.
     *
     * @param  string $in
     * @param  bool   $dashed
     * @return string
     * @internal
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
     *
     * @param  string $in
     * @param  bool   $dashed
     * @param  bool   $guid
     * @return string
     * @internal
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
