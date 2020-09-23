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

namespace froq\encrypting\twoway;

use froq\encrypting\{Salt, Base, Base64};
use froq\encrypting\twoway\TwowayException;

/**
 * Twoway.
 * @package froq\encrypting\twoway
 * @object  froq\encrypting\twoway\Twoway
 * @author  Kerem Güneş <k-gun@mail.com>
 * @since   3.0
 */
abstract class Twoway
{
    /**
     * Key.
     * @var string
     */
    protected string $key;

    /**
     * Constructor.
     * @param string $key
     */
    public function __construct(string $key)
    {
        $this->key = $key;
    }

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
    public static final function generateKey(int $length = 40): string
    {
        return Salt::generate($length);
    }

    /**
     * Encrypt.
     * @param  string $data
     * @param  array  $options
     * @return ?string
     * @since  4.5
     */
    public static final function encrypt(string $data, array $options): ?string
    {
        $instance = new static(
            // Key is required, nonce for Sodium, method for OpenSsl.
            $options['key'] ?? '', $options['nonce'] ?? $options['method'] ?? null
        );

        if (isset($options['type'])) {
            $data = $instance->encode($data, true);
            switch ($options['type']) {
                case 'base62':
                    $data && $data = Base::encode($data);
                    break;
                case 'base64':
                    $data && $data = Base64::encode($data);
                    break;
                case 'base64url':
                    $data && $data = Base64::encodeUrlSafe($data);
                    break;
                default:
                    throw new TwowayException('Invalid type "%s" given, valids are: base62, base64, base64url',
                        [$options['type']]);
            }

            return $data;
        }

        return $instance->encode($data);
    }

    /**
     * Decrypt.
     * @param  string $data
     * @param  array  $options
     * @return ?string
     * @since  4.5
     */
    public static final function decrypt(string $data, array $options): ?string
    {
        $instance = new static(
            // Key is required, nonce for Sodium, method for OpenSsl.
            $options['key'] ?? '', $options['nonce'] ?? $options['method'] ?? null
        );

        if (isset($options['type'])) {
            switch ($options['type']) {
                case 'base62':
                    $data = Base::decode($data);
                    break;
                case 'base64':
                    $data = Base64::decode($data);
                    break;
                case 'base64url':
                    $data = Base64::decodeUrlSafe($data);
                    break;
                default:
                    throw new TwowayException('Invalid type "%s" given, valids are: base62, base64, base64url',
                        [$options['type']]);
            }

            return $instance->decode($data, true);
        }

        return $instance->decode($data);
    }

    /**
     * Encode.
     * @param  string $data
     * @param  bool   $raw
     * @return ?string
     */
    public abstract function encode(string $data, bool $raw = false): ?string;

    /**
     * Decode.
     * @param  string $data
     * @param  bool   $raw
     * @return ?string
     */
    public abstract function decode(string $data, bool $raw = false): ?string;
}
