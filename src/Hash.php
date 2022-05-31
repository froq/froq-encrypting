<?php
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-encrypting
 */
declare(strict_types=1);

namespace froq\encrypting;

/**
 * A static class, generates hashes by given lengths.
 *
 * @package froq\encrypting
 * @object  froq\encrypting\Hash
 * @author  Kerem Güneş
 * @since   4.0
 * @static
 */
final class Hash
{
    /** @const array */
    public const ALGOS = [
        8  => 'fnv1a32', 16 => 'fnv1a64', 32  => 'md5',
        40 => 'sha1',    64 => 'sha256',  128 => 'sha512'
    ];

    /**
     * Make a hash by given length.
     *
     * @param  string     $input
     * @param  int        $length
     * @param  array|null $lengths @internal
     * @return string
     * @throws froq\encrypting\EncryptingException
     */
    public static function make(string $input, int $length, array $lengths = null): string
    {
        $lengths ??= array_keys(self::ALGOS);

        if (!in_array($length, $lengths, true)) {
            throw new EncryptingException(
                'Invalid length `%s` [valids: %A]',
                [$length, $lengths]
            );
        }

        $algo = self::ALGOS[$length];

        return hash($algo, $input);
    }

    /**
     * Make a hash by given algo.
     *
     * @param  string $input
     * @param  string $algo
     * @return string
     * @throws froq\encrypting\EncryptingException
     * @since  6.0
     */
    public static function makeBy(string $input, string $algo): string
    {
        if (!in_array($algo, hash_algos(), true)) {
            throw new EncryptingException(
                'Invalid algo %s [valids: %A]',
                [$algo, hash_algos()]
            );
        }

        return hash($algo, $input);
    }
}
