<?php
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-encrypting
 */
declare(strict_types=1);

namespace froq\encrypting\twoway;

/**
 * Sodium.
 *
 * A class, able to perform twoway encrypting operations utilizing Sodium extension.
 *
 * @package froq\encrypting\twoway
 * @object  froq\encrypting\twoway\Sodium
 * @author  Kerem Güneş
 * @since   3.0
 */
final class Sodium extends Twoway
{
    /** @var string */
    private string $nonce;

    /**
     * Constructor.
     *
     * @param  string $key
     * @param  string $nonce
     * @throws froq\encrypting\twoway\TwowayException
     */
    public function __construct(string $key, string $nonce)
    {
        if (!extension_loaded('sodium')) {
            throw new TwowayException('Sodium extension not loaded');
        }

        $keyLength = strlen($key);

        // Check key length.
        if ($keyLength < 16) {
            throw new TwowayException(
                'Invalid key length `%s`, minimum key length is 16 '.
                '[tip: use %s::generateKey() method to get a key]',
                [$keyLength, self::class]
            );
        }

        // Key size must be 32-length.
        if ($keyLength != SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            $key = md5($key);
        }

        // Check nonce length.
        if (strlen($nonce) != SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
            throw new TwowayException(
                'Invalid nonce length `%s`, nonce length must be %s',
                [strlen($nonce), SODIUM_CRYPTO_SECRETBOX_NONCEBYTES]
            );
        }

        $this->nonce = $nonce;

        parent::__construct($key);
    }

    /**
     * Get nonce property.
     *
     * @return string
     */
    public function nonce(): string
    {
        return $this->nonce;
    }

    /**
     * @inheritDoc froq\encrypting\twoway\Twoway
     */
    public function encrypt(string $input, bool $raw = false): string|null
    {
        try {
            $ret = sodium_crypto_secretbox($input, $this->nonce, $this->key);
            if ($ret !== false) {
                return $raw ? $ret : base64_encode($ret);
            }
        } catch (\SodiumException) {}

        return null;
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

        try {
            $ret = sodium_crypto_secretbox_open($input, $this->nonce, $this->key);
            if ($ret !== false) {
                return $ret;
            }
        } catch (\SodiumException) {}

        return null;
    }
}
