<?php
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-encrypting
 */
declare(strict_types=1);

namespace froq\encrypting;

/**
 * A static class, able to generate UUIDs (v4) from random bytes and optionally with
 * timestamp/namespaces or GUIDs from random bytes and hashes of these with/without
 * given lengths, also to generate time-based or random serials.
 *
 * @package froq\encrypting
 * @object  froq\encrypting\Uuid
 * @author  Kerem Güneş
 * @since   3.0
 * @static
 */
class Uuid
{
    /** @const string */
    public const NULL      = '00000000-0000-0000-0000-000000000000',
                 NULL_HASH = '00000000000000000000000000000000';

    /** @const int */
    public const HASH_LENGTH = 32;

    /** @const array<int> */
    public const HASH_LENGTHS = [32, 16, 40, 64];

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
     * @throws froq\encrypting\UuidException
     * @since  4.3
     */
    public static function generateHash(int $hashLength = self::HASH_LENGTH, bool $format = false): string
    {
        $hash = Hash::make(self::generate(false), $hashLength, self::HASH_LENGTHS);

        if ($format) {
            if ($hashLength != self::HASH_LENGTH) {
                throw new UuidException('Format option for only 32-length hashes');
            }

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
     * @throws froq\encrypting\UuidException
     * @since  4.8
     */
    public static function generateGuidHash(int $hashLength = self::HASH_LENGTH, bool $format = false): string
    {
        $hash = Hash::make(self::generateGuid(false), $hashLength, self::HASH_LENGTHS);

        if ($format) {
            if ($hashLength != self::HASH_LENGTH) {
                throw new UuidException('Format option for only 32-length hashes');
            }

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
     * @since  4.6, 4.9
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
     * @throws froq\encrypting\UuidException
     * @since  4.6, 4.9
     */
    public static function generateWithTimestampHash(int $hashLength = self::HASH_LENGTH, bool $format = false): string
    {
        $hash = Hash::make(self::generateWithTimestamp(false), $hashLength, self::HASH_LENGTHS);

        if ($format) {
            if ($hashLength != self::HASH_LENGTH) {
                throw new UuidException('Format option for only 32-length hashes');
            }

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
        $nshash = md5($namespace);
        $prefix = dechex(hexdec(substr($nshash, 0, 2))) . substr($nshash, 2, 10);

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
     * @throws froq\encrypting\UuidException
     * @since  4.9
     */
    public static function generateWithNamespaceHash(string $namespace, int $hashLength = self::HASH_LENGTH, bool $format = false): string
    {
        $hash = Hash::make(self::generateWithNamespace($namespace, false), $hashLength, self::HASH_LENGTHS);

        if ($format) {
            if ($hashLength != self::HASH_LENGTH) {
                throw new UuidException('Format option for only 32-length hashes');
            }

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
     * @since  4.0, 4.8
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
     * @since  4.0, 4.8
     */
    public static function generateRandomSerial(bool $dashed = true, bool $hexed = false): string
    {
        $serial = Generator::generateRandomId(32, ($hexed ? 16 : 10));

        return self::format($serial, $dashed);
    }

    /**
     * Check whether given input a valid UUID/v4 or GUID.
     *
     * @param  string $input
     * @param  bool   $strict
     * @return bool
     * @since  5.0
     */
    public static function isValid(string $input, bool $strict = true): bool
    {
        return self::validate($input, $strict);
    }

    /**
     * Check whether given input is a valid hash.
     *
     * @param  string $input
     * @param  int    $length
     * @return bool
     * @since  5.0
     */
    public static function isValidHash(string $input, int $length = self::HASH_LENGTH): bool
    {
        return self::validateHash($input, $length);
    }

    /**
     * Validate given input as UUUD/v4 or GUID.
     *
     * @param  string $input
     * @param  bool   $strict
     * @return bool
     */
    public static function validate(string $input, bool $strict = true): bool
    {
        if ($strict) {
            // With version, variant & dashes.
            return preg_test(
                '~^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[ab89][a-f0-9]{3}-[a-f0-9]{12}$~',
                $input
            );
        }

        // With/without version, variant & dashes.
        return preg_test(
            '~^[a-f0-9]{8}-?[a-f0-9]{4}-?[a-f0-9]{4}-?[a-f0-9]{4}-?[a-f0-9]{12}$~',
            $input
        );
    }

    /**
     * Validate given input as hash by length.
     *
     * @param  string $input
     * @param  int    $length
     * @return bool
     */
    public static function validateHash(string $input, int $length = self::HASH_LENGTH): bool
    {
        // With given length.
        return preg_test('~^[a-f0-9]{' . $length . '}$~', $input);
    }

    /**
     * Format.
     *
     * @param  string $input
     * @param  bool   $dashed
     * @return string
     * @throws froq\encrypting\UuidException
     */
    public static function format(string $input, bool $dashed = true): string
    {
        if (strlen($input) != self::HASH_LENGTH || !ctype_xdigit($input)) {
            throw new UuidException('Input must be a 32-length x-digit');
        }

        $ret = vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split($input, 4));

        // Drop dashes if false.
        $dashed || $ret = str_replace('-', '', $ret);

        return $ret;
    }

    /**
     * Format binary.
     *
     * @param  string $input
     * @param  bool   $dashed
     * @param  bool   $guid
     * @return string
     * @causes froq\encrypting\UuidException
     */
    public static function formatBinary(string $input, bool $dashed = true, bool $guid = false): string
    {
        // GUID doesn't use 4 (version) or 8, 9, A, B.
        if (!$guid) {
            $input[6] = chr(ord($input[6]) & 0x0f | 0x40);
            $input[8] = chr(ord($input[8]) & 0x3f | 0x80);
        }

        return self::format(bin2hex($input), $dashed);
    }
}
