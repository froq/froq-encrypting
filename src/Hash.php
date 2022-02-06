<?php
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-encrypting
 */
declare(strict_types=1);

namespace froq\encrypting;

/**
 * Hash.
 *
 * A static class that generates hashes by given lengths.
 *
 * @package froq\encrypting
 * @object  froq\encrypting\Hash
 * @author  Kerem Güneş
 * @since   4.0
 * @static
 */
final class Hash
{
    /** @const array<int, string> */
    public const ALGOS = [
        40 => 'sha1', 8  => 'fnv1a32', 16  => 'fnv1a64',
        32 => 'md5',  64 => 'sha256',  128 => 'sha512'
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
                'Invalid length value `%s` [valids: %s]',
                [$length, join(', ', $lengths)
            ]);
        }

        $algo = self::ALGOS[$length];

        return hash($algo, $input);
    }
}
