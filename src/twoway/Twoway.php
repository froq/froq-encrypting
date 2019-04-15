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

namespace froq\encryption\twoway;

use froq\encryption\Encryption;

/**
 * Twoway.
 * @package froq\encryption\twoway
 * @object  froq\encryption\twoway\Twoway
 * @author  Kerem Güneş <k-gun@mail.com>
 * @since   3.0
 */
abstract class Twoway
{
    /**
     * Key.
     * @var string
     */
    protected $key;

    /**
     * Get key.
     * @return string
     */
    public final function getKey(): string
    {
        return $this->key;
    }

    /**
     * Generate key.
     * @param  int $length
     * @return string
     */
    public static final function generateKey(int $length = 64): string
    {
        return Encryption::generateNonce($length);
    }

    /**
     * Encode.
     * @param  string $data
     * @return ?string
     */
    public abstract function encode(string $data): ?string;

    /**
     * Decode.
     * @param  string $data
     * @return ?string
     */
    public abstract function decode(string $data): ?string;
}
