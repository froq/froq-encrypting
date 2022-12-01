<?php declare(strict_types=1);
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-encrypting
 */
namespace froq\encrypting\twoway;

/**
 * A class, able to perform twoway encrypting operations utilizing OpenSSL extension.
 * Original source: https://stackoverflow.com/a/30189841/362780
 *
 * @package froq\encrypting\twoway
 * @class   froq\encrypting\twoway\OpenSsl
 * @author  Kerem Güneş
 * @since   3.0
 */
class OpenSsl extends Twoway
{
    /** Default cipher method. */
    public const CIPHER_METHOD = 'aes-256-ctr';

    /**
     * Constructor.
     *
     * @param  string      $key
     * @param  string|null $method
     * @param  array|null  $options
     * @throws froq\encrypting\twoway\TwowayException
     */
    public function __construct(string $key, string $method = null, array $options = null)
    {
        if (!extension_loaded('openssl')) {
            throw new TwowayException('OpenSSL extension not loaded');
        }

        parent::checkKeyLength(strlen($key));

        // Check method validity.
        if ($method) {
            $method = strtolower($method);
            if (!in_array($method, openssl_get_cipher_methods(), true)) {
                throw new TwowayException('Invalid cipher method %q', $method);
            }
        }

        $options = ['key' => $key, 'method' => $method ?? self::CIPHER_METHOD] + (array) $options;

        parent::__construct($options);
    }

    /**
     * @inheritDoc froq\encrypting\twoway\Twoway
     */
    public function encrypt(string $input, bool $raw = false): string|null
    {
        [$encKey, $autKey] = $this->keys();

        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($this->options['method']));

        $ret = openssl_encrypt($input, $this->options['method'], $encKey, OPENSSL_RAW_DATA, $iv);

        if ($ret === false) {
            return null;
        }

        $ret = $iv . $ret;
        $mac = hash_hmac('sha256', $ret, $autKey, true);
        $ret = $mac . $ret;

        return $raw ? $ret : $this->encode($ret);
    }

    /**
     * @inheritDoc froq\encrypting\twoway\Twoway
     */
    public function decrypt(string $input, bool $raw = false): string|null
    {
        $input = $raw ? $input : $this->decode($input);

        // Invalid.
        if ($input === null) {
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

        $ivLen = openssl_cipher_iv_length($this->options['method']);
        $iv    = mb_substr($input, 0, $ivLen, '8bit');
        $input = mb_substr($input, $ivLen, null, '8bit');

        $ret = openssl_decrypt($input, $this->options['method'], $encKey, OPENSSL_RAW_DATA, $iv);

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
            hash_hmac('sha256', '_ENC_', $this->options['key'], true),
            hash_hmac('sha256', '_AUT_', $this->options['key'], true)
        ];
    }
}
