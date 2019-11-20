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

use froq\encryption\EncryptionException;
use SodiumException;

/**
 * Sodium.
 * @package froq\encryption\twoway
 * @object  froq\encryption\twoway\Sodium
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
     * @param  string      $key
     * @param  string|null $nonce
     * @throws froq\encryption\EncryptionException
     */
    public function __construct(string $key, string $nonce = null)
    {
        if (!extension_loaded('sodium')) {
            throw new EncryptionException('Sodium extension not found');
        }

        // Check key length.
        if (strlen($key) < 16) {
            throw new EncryptionException('Invalid key given, minimum key length is 16 (tip: use '.
                'Sodium::generateKey() method to get a strong key)');
        }

        // Check nonce length.
        if ($nonce != null && strlen($nonce) != 24) {
            throw new EncryptionException('Invalid nonce given, nonce length should be 24');
        }

        // Key size should be SODIUM_CRYPTO_SECRETBOX_KEYBYTES.
        $this->key = md5($key);
        $this->nonce = $nonce ?? random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
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
     * @inheritDoc froq\encryption\twoway\Twoway
     */
    public function encode(string $data): ?string
    {
        try {
            $out = sodium_crypto_secretbox($data, $this->nonce, $this->key);
            return ($out !== false) ? base64_encode($out) : null;
        } catch (SodiumException $e) {
            return null;
        }
    }

    /**
     * @inheritDoc froq\encryption\twoway\Twoway
     */
    public function decode(string $data): ?string
    {
        try {
            $out = sodium_crypto_secretbox_open(base64_decode($data), $this->nonce, $this->key);
            return ($out !== false) ? $out : null;
        } catch (SodiumException $e) {
            return null;
        }
    }
}
