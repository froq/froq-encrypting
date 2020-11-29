<?php
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 <https://opensource.org/licenses/apache-2.0>
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

        $this->method = $method ?? self::METHOD;

        parent::__construct($key);
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
    public function encode(string $data, bool $raw = false): ?string
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

        return !$raw ? base64_encode($out) : $out;
    }

    /**
     * @inheritDoc froq\encrypting\twoway\Twoway
     */
    public function decode(string $data, bool $raw = false): ?string
    {
        $data = !$raw ? base64_decode($data, true) : $data;

        [$encKey, $autKey] = $this->keys();

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
