<?php
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-encrypting
 */
declare(strict_types=1);

namespace froq\encrypting\twoway;

/**
 * Open Ssl.
 *
 * A class, able to perform twoway encrypting operations utilizing OpenSsl extension.
 * Original source https://stackoverflow.com/a/30189841/362780.
 *
 * @package froq\encrypting\twoway
 * @object  froq\encrypting\twoway\OpenSsl
 * @author  Kerem Güneş
 * @since   3.0
 */
final class OpenSsl extends Twoway
{
    /**
     * Default method.
     * @const string
     */
    public const METHOD = 'aes-256-ctr';

    /** @var string */
    private string $method;

    /**
     * Constructor.
     *
     * @param  string      $key
     * @param  string|null $method
     * @throws froq\encrypting\twoway\TwowayException
     */
    public function __construct(string $key, string $method = null)
    {
        if (!extension_loaded('openssl')) {
            throw new TwowayException('Openssl extension not loaded');
        }

        // Check key length.
        if (strlen($key) < 16) {
            throw new TwowayException(
                'Invalid key length `%s`, minimum key length is 16 '.
                '[tip: use %s::generateKey() method to get a key]',
                [strlen($key), self::class]
            );
        }

        // Check method validity.
        if ($method) {
            $method = strtolower($method);
            if (!in_array($method, openssl_get_cipher_methods(), true)) {
                throw new TwowayException('Invalid cipher method `%s`', $method);
            }
        }

        $this->method = $method ?? self::METHOD;

        parent::__construct($key);
    }

    /**
     * Get method property.
     *
     * @return string
     */
    public function method(): string
    {
        return $this->method;
    }

    /**
     * @inheritDoc froq\encrypting\twoway\Twoway
     */
    public function encrypt(string $input, bool $raw = false): string|null
    {
        [$encKey, $autKey] = $this->keys();

        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($this->method));

        $ret = openssl_encrypt($input, $this->method, $encKey, OPENSSL_RAW_DATA, $iv);
        if ($ret === false) {
            return null;
        }

        $ret = $iv . $ret;
        $mac = hash_hmac('sha256', $ret, $autKey, true);
        $ret = $mac . $ret;

        return $raw ? $ret : base64_encode($ret);
    }

    /**
     * @inheritDoc froq\encrypting\twoway\Twoway
     */
    public function decrypt(string $input, bool $raw = false): string|null
    {
        $input = $raw ? $input : base64_decode($input, true);

        // Invalid.
        if ($input === false) {
            return null;
        }

        [$encKey, $autKey] = $this->keys();

        $macLen = mb_strlen(hash('sha256', '', true), '8bit');
        $mac    = mb_substr($input, 0, $macLen, '8bit');
        $input  = mb_substr($input, $macLen, null, '8bit');

        // Validate hashes.
        if (!hash_equals($mac, hash_hmac('sha256', $input, $autKey, true))) {
            return null;
        }

        $ivLen = openssl_cipher_iv_length($this->method);
        $iv    = mb_substr($input, 0, $ivLen, '8bit');
        $input = mb_substr($input, $ivLen, null, '8bit');

        $ret = openssl_decrypt($input, $this->method, $encKey, OPENSSL_RAW_DATA, $iv);
        if ($ret === false) {
            return null;
        }

        return $ret;
    }

    /**
     * Keys.
     */
    private function keys(): array
    {
        return [
            hash_hmac('sha256', '_ENC_', $this->key, true),
            hash_hmac('sha256', '_AUT_', $this->key, true)
        ];
    }
}
