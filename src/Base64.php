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
     * @param  string $in
     * @return string
     */
    public static function encode(string $in): string
    {
        return (string) base64_encode($in);
    }

    /**
     * Decode.
     * @param  string $in
     * @param  bool   $strict
     * @return string
     */
    public static function decode(string $in, bool $strict = false): string
    {
        return (string) base64_decode($in, $strict);
    }

    /**
     * Encode URL-safe.
     * @param  string $in
     * @return string
     */
    public static function encodeUrlSafe(string $in): string
    {
        return chop(strtr((string) base64_encode($in), '/+', '_-'), '=');
    }

    /**
     * Decode URL-safe.
     * @param  string $in
     * @param  bool   $strict
     * @return string
     */
    public static function decodeUrlSafe(string $in, bool $strict = false): string
    {
        return (string) base64_decode(strtr($in, '_-', '/+'), $strict);
    }
}
