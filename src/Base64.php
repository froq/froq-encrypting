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
 * A static class, provides a Base-64 encoding/decoding methods and URL-safe stuff.
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
     * @param  string $input
     * @return string
     */
    public static function encode(string $input): string
    {
        return base64_encode($input);
    }

    /**
     * Decode given input.
     *
     * @param  string $input
     * @param  bool   $strict
     * @return string
     */
    public static function decode(string $input, bool $strict = false): string
    {
        return (string) base64_decode($input, $strict);
    }

    /**
     * Encode given input with URL-safe method.
     *
     * @param  string $input
     * @return string
     */
    public static function encodeUrlSafe(string $input): string
    {
        return chop(strtr(base64_encode($input), '/+', '_-'), '=');
    }

    /**
     * Decode given input with URL-safe method.
     *
     * @param  string $input
     * @param  bool   $strict
     * @return string
     */
    public static function decodeUrlSafe(string $input, bool $strict = false): string
    {
        return (string) base64_decode(strtr($input, '_-', '/+'), $strict);
    }
}
