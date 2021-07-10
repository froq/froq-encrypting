<?php
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-encrypting
 */
declare(strict_types=1);

namespace froq\encrypting;

/**
 * Base 64.
 *
 * Represents a static class which provides a Base-64 encoding/decoding methods and also URL-safe stuff.
 *
 * @package froq\encrypting
 * @object  froq\encrypting\Base64
 * @author  Kerem Güneş
 * @since   4.2
 * @static
 */
final class Base64
{
    /**
     * Encode given input.
     *
     * @param  string $in
     * @return string
     */
    public static function encode(string $in): string
    {
        return (string) base64_encode($in);
    }

    /**
     * Decode given input.
     *
     * @param  string $in
     * @param  bool   $strict
     * @return string
     */
    public static function decode(string $in, bool $strict = false): string
    {
        return (string) base64_decode($in, $strict);
    }

    /**
     * Encode given input with URL-safe method.
     *
     * @param  string $in
     * @return string
     */
    public static function encodeUrlSafe(string $in): string
    {
        return chop(strtr(self::encode($in), '/+', '_-'), '=');
    }

    /**
     * Decode given input with URL-safe method.
     *
     * @param  string $in
     * @param  bool   $strict
     * @return string
     */
    public static function decodeUrlSafe(string $in, bool $strict = false): string
    {
        return self::decode(strtr($in, '_-', '/+'), $strict);
    }
}
