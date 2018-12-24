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

namespace Froq\Encryption;

/**
 * @package    Froq
 * @subpackage Froq\Encryption
 * @object     Froq\Encryption\Encryption
 * @author     Kerem Güneş <k-gun@mail.com>
 */
final class Encryption
{
    /**
     * Generate salt.
     * @param  int|null $length
     * @param  bool     $translate
     * @return string
     */
    public static function generateSalt(int $length = null, bool $translate = false): string
    {
        return Salt::generate($length, $translate);
    }

    /**
     * Generate uuid.
     * @param  int|null $type
     * @param  bool     $translate
     * @return string
     */
    public static function generateUuid(int $type = null, bool $translate = false): string
    {
        return Uuid::generate($type, $translate);
    }

    /**
     * Generate nonce.
     * @param  int $length
     * @return string
     * @throws Froq\Encryption\EncryptionException
     */
    public static function generateNonce(int $length = 40): string
    {
        static $algos = [8 => 'fnv132', 16 => 'fnv164', 32 => 'md5', 40 => 'sha1',
            64 => 'sha256', 128 => 'sha512'];

        if (isset($algos[$length])) {
            return hash($algos[$length], random_bytes($length / 2));
        }

        throw new EncryptionException(sprintf("Given '{$length}' not implemented, '%s' are accepted!",
            join(',', array_keys($algos))));
    }
}
