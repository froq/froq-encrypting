<?php declare(strict_types=1);
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-encrypting
 */
namespace froq\encrypting;

/**
 * A static class, generates tokens.
 *
 * @package froq\encrypting
 * @class   froq\encrypting\Token
 * @author  Kerem Güneş
 * @since   7.1
 * @static
 */
class Token
{
    /** Length. */
    public const LENGTH = 40;

    /**
     * Generate a token (hash) by given length.
     *
     * @param  int         $length
     * @param  string|null $prefix For more safety.
     * @return string
     * @throws froq\encrypting\TokenException
     */
    public static function generate(int $length = null, string $prefix = null): string
    {
        // Auto-generate, if none.
        $prefix ??= random_bytes(10);

        try {
            return Hash::make(
                uniqid($prefix, true),
                length: $length ?? static::LENGTH,
                lengths: [40, 16, 32, 64] // Allowed.
            );
        } catch (HashException $e) {
            throw new TokenException($e);
        }
    }
}
