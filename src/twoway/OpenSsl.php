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
use froq\encryption\twoway\Twoway;

/**
 * Open Ssl.
 *
 * Original source https://stackoverflow.com/a/30189841/362780.
 *
 * @package froq\encryption\twoway
 * @object  froq\encryption\twoway\OpenSsl
 * @author  Kerem Güneş <k-gun@mail.com>
 * @since   3.0
 */
final class OpenSsl extends Twoway
{
    /**
     * Method.
     * @const string
     */
    public const METHOD = 'aes-256-ctr';

    /**
     * Method.
     * @var string
     */
    private string $method;

    /**
     * Constructor.
     * @param  string      $key
     * @param  string|null $method
     * @throws froq\encryption\EncryptionException
     */
    public function __construct(string $key, string $method = null)
    {
        if (!extension_loaded('openssl')) {
            throw new EncryptionException('OpenSSL extension not found');
        }

        // Check key length.
        if (strlen($key) < 16) {
            throw new EncryptionException('Invalid key given, minimum key length is 16 (tip: use '.
                'OpenSSL::generateKey() method to get a strong key)');
        }

        // Check method validity.
        if (!in_array($method, openssl_get_cipher_methods())) {
            throw new EncryptionException("Invalid method '{$method}' given");
        }

        parent::__construct($key);

        $this->method = $method ?? self::METHOD;
    }

    /**
     * Get method.
     * @return string
     */
    public function getMethod(): string
    {
        return $this->method;
    }

    /**
     * @inheritDoc froq\encryption\twoway\Twoway
     */
    public function encode(string $data): ?string
    {
        [$eKey, $aKey] = $this->keys();

        $out = openssl_encrypt($data, $this->method, $eKey, OPENSSL_RAW_DATA,
            $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($this->method)));
        $out = $iv . $out;

        $mac = hash_hmac('sha256', $out, $aKey, true);
        $out = $mac . $out;

        return (string) base64_encode($out);
    }

    /**
     * @inheritDoc froq\encryption\twoway\Twoway
     */
    public function decode(string $data): ?string
    {
        [$eKey, $aKey] = $this->keys();

        $data = base64_decode($data, true);

        $macLen = mb_strlen(hash('sha256', '', true), '8bit');
        $mac = mb_substr($data, 0, $macLen, '8bit');
        $data = mb_substr($data, $macLen, null, '8bit');

        // Validate hashes.
        if (!hash_equals($mac, hash_hmac('sha256', $data, $aKey, true))) {
            return null;
        }

        $ivLen = openssl_cipher_iv_length($this->method);
        $iv = mb_substr($data, 0, $ivLen, '8bit');
        $data = mb_substr($data, $ivLen, null, '8bit');

        return (string) openssl_decrypt($data, $this->method, $eKey, OPENSSL_RAW_DATA, $iv);
    }

    /**
     * Keys.
     * @return array<binary>
     * @internal
     */
    private function keys(): array
    {
        return [
            hash_hmac('sha256', 'ENCRYPTION', $this->key, true),
            hash_hmac('sha256', 'AUTHENTICATION', $this->key, true)
        ];
    }
}
