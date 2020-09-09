<?php
/**
 * MIT License <https://opensource.org/licenses/mit>
 *
 * Copyright (c) 2015 Kerem Güneş
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is furnished
 * to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
declare(strict_types=1);

namespace froq\encrypting;

/**
 * Base64.
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
