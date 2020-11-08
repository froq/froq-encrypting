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

use froq\encrypting\twoway\{Twoway, TwowayException};
use SodiumException;

/**
 * Sodium.
 * @package froq\encrypting\twoway
 * @object  froq\encrypting\twoway\Sodium
 * @author  Kerem Güneş <k-gun@mail.com>
 * @since   3.0
 */
final class Sodium extends Twoway
{
    /**
     * Nonce.
     * @var string
     */
    private string $nonce;

    /**
     * Constructor.
     * @param  string $key
     * @param  string $nonce
     * @throws froq\encrypting\twoway\TwowayException
     */
    public function __construct(string $key, string $nonce)
    {
        if (!extension_loaded('sodium')) {
            throw new TwowayException('sodium extension not loaded');
        }

        $keyLength = strlen($key);

        // Check key length.
        if ($keyLength < 16) {
            throw new TwowayException('Invalid key given, minimum key length is 16 (tip: use '.
                'Sodium::generateKey() method to get a strong key)');
        }

        // Key size must be 32-length.
        if ($keyLength != SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            $key = md5($key);
        }

        // Check nonce length.
        if (strlen($nonce) != SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
            throw new TwowayException('Invalid nonce given, nonce length must be '.
                SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        }

        $this->nonce = $nonce;

        parent::__construct($key);
    }

    /**
     * Get nonce.
     * @return string
     */
    public function getNonce(): string
    {
        return $this->nonce;
    }

    /**
     * @inheritDoc froq\encrypting\twoway\Twoway
     */
    public function encode(string $data, bool $raw = false): ?string
    {
        try {
            $out =@ sodium_crypto_secretbox($data, $this->nonce, $this->key);
            if ($out !== false) {
                return !$raw ? base64_encode($out) : $out;
            }
        } catch (SodiumException $e) {}

        return null;
    }

    /**
     * @inheritDoc froq\encrypting\twoway\Twoway
     */
    public function decode(string $data, bool $raw = false): ?string
    {
        $data = !$raw ? base64_decode($data, true) : $data;

        try {
            $out =@ sodium_crypto_secretbox_open($data, $this->nonce, $this->key);
            if ($out !== false) {
                return $out;
            }
        } catch (SodiumException $e) {}

        return null;
    }
}
