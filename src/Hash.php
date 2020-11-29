<?php
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 <https://opensource.org/licenses/apache-2.0>
 */
declare(strict_types=1);

namespace froq\encrypting;

use froq\encrypting\EncryptingException;

/**
 * Hash.
 *
 * @package froq\encrypting
 * @object  froq\encrypting\Hash
 * @author  Kerem Güneş <k-gun@mail.com>
 * @since   4.0
 * @static
 */
final class Hash
{
    /**
     * Algos.
     * @const array<int, string>
     */
    public const ALGOS = [40 => 'sha1', 8 => 'fnv1a32', 16 => 'fnv1a64', 32 => 'md5',
        64 => 'sha256', 128 => 'sha512'];

    /**
     * Hash.
     * @param  string     $input
     * @param  int        $length
     * @param  array|null $lengths
     * @return string
     * @throws froq\encrypting\EncryptingException
     */
    public static function make(string $input, int $length, array $lengths = null): string
    {
        $lengths = $lengths ?? array_keys(self::ALGOS);

        if (!in_array($length, $lengths, true)) {
            throw new EncryptingException("Invalid length value '%s' given, valids are: %s",
                [$length, join(', ', $lengths)]);
        }

        $algo = self::ALGOS[$length];

        return hash($algo, $input);
    }
}
