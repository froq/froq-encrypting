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

/**
 * Open Ssl.
 *
 * Original source https://stackoverflow.com/a/30189841/362780.
 *
 * @package froq\encrypting\twoway
 * @object  froq\encrypting\twoway\OpenSsl
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
     * @throws froq\encrypting\twoway\TwowayException
     */
    public function __construct(string $key, string $method = null)
    {
        if (!extension_loaded('openssl')) {
            throw new TwowayException('openssl extension not found');
        }

        // Check key length.
        if (strlen($key) < 16) {
            throw new TwowayException('Invalid key given, minimum key length is 16 (tip: use '.
                'OpenSSL::generateKey() method to get a strong key)');
        }

        // Check method validity.
        if ($method && !in_array($method, openssl_get_cipher_methods())) {
            throw new TwowayException('Invalid method "%s" given', [$method]);
        }

        parent::__construct($key);

        $this->method = $method ?: self::METHOD;
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
     * @inheritDoc froq\encrypting\twoway\Twoway
     */
    public function encode(string $data): ?string
    {
        [$encKey, $autKey] = $this->keys();

        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($this->method));

        $out =@ openssl_encrypt($data, $this->method, $encKey, OPENSSL_RAW_DATA, $iv);
        if ($out === false) {
            return null;
        }

        $out = $iv . $out;
        $mac = hash_hmac('sha256', $out, $autKey, true);
        $out = $mac . $out;

        return base64_encode($out);
    }

    /**
     * @inheritDoc froq\encrypting\twoway\Twoway
     */
    public function decode(string $data): ?string
    {
        [$encKey, $autKey] = $this->keys();

        $data   = base64_decode($data, true);
        $macLen = mb_strlen(hash('sha256', '', true), '8bit');
        $mac    = mb_substr($data, 0, $macLen, '8bit');
        $data   = mb_substr($data, $macLen, null, '8bit');

        // Validate hashes.
        if (!hash_equals($mac, hash_hmac('sha256', $data, $autKey, true))) {
            return null;
        }

        $ivLen = openssl_cipher_iv_length($this->method);
        $iv    = mb_substr($data, 0, $ivLen, '8bit');
        $data  = mb_substr($data, $ivLen, null, '8bit');

        $out =@ openssl_decrypt($data, $this->method, $encKey, OPENSSL_RAW_DATA, $iv);
        if ($out === false) {
            return null;
        }

        return $out;
    }

    /**
     * Keys.
     * @return array<binary>
     * @internal
     */
    private function keys(): array
    {
        return [
            hash_hmac('sha256', '_ENC_', $this->key, true),
            hash_hmac('sha256', '_AUT_', $this->key, true)
        ];
    }
}
