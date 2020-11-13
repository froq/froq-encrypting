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

use froq\encrypting\EncryptingException;

/**
 * Hash.
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
            throw new EncryptingException('Invalid length value "%s" given, valids are: %s',
                [$length, join(', ', $lengths)]);
        }

        $algo = self::ALGOS[$length];

        return hash($algo, $input);
    }
}
