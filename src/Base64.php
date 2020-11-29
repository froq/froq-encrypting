<?php
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 <https://opensource.org/licenses/apache-2.0>
 */
declare(strict_types=1);

namespace froq\encrypting;

/**
 * Base 64.
 *
 * @package froq\encrypting
 * @object  froq\encrypting\Base64
 * @author  Kerem Güneş <k-gun@mail.com>
 * @since   4.2
 * @static
 */
final class Base64
{
    /**
     * Encode.
     * @param  string $input
     * @return string
     */
    public static function encode(string $input): string
    {
        return (string) base64_encode($input);
    }

    /**
     * Decode.
     * @param  string $input
     * @param  bool   $strict
     * @return string
     */
    public static function decode(string $input, bool $strict = false): string
    {
        return (string) base64_decode($input, $strict);
    }

    /**
     * Encode URL-safe.
     * @param  string $input
     * @return string
     */
    public static function encodeUrlSafe(string $input): string
    {
        return chop(strtr((string) base64_encode($input), '/+', '_-'), '=');
    }

    /**
     * Decode URL-safe.
     * @param  string $input
     * @param  bool   $strict
     * @return string
     */
    public static function decodeUrlSafe(string $input, bool $strict = false): string
    {
        return (string) base64_decode(strtr($input, '_-', '/+'), $strict);
    }
}
