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
    /**
     * Constructor.
     *
     * @param  string     $key
     * @param  string     $nonce
     * @param  array|null $options
     * @throws froq\encrypting\twoway\TwowayException
     */
    public function __construct(string $key, string $nonce, array $options = null)
    {
        if (!extension_loaded('sodium')) {
            throw new TwowayException('Sodium extension not loaded');
        }

        parent::checkKeyLength($keyLength = strlen($key));

        // Key length must be 32-length.
        if ($keyLength != SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            throw new TwowayException(
                'Invalid key length `%s`, key length must be %s',
                [$keyLength, SODIUM_CRYPTO_SECRETBOX_KEYBYTES]
            );
        }

        // Nonce length must be 32-length.
        if (strlen($nonce) != SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
            throw new TwowayException(
                'Invalid nonce length `%s`, nonce length must be %s',
                [strlen($nonce), SODIUM_CRYPTO_SECRETBOX_NONCEBYTES]
            );
        }

        $options = ['key' => $key, 'nonce' => $nonce] + (array) $options;

        parent::__construct($options);
    }

    /**
     * @inheritDoc froq\encrypting\twoway\Twoway
     */
    public function encrypt(string $input, bool $raw = false): string|null
    {
        $ret = sodium_crypto_secretbox(
            $input, $this->options['nonce'], $this->options['key']
        );

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

        return sodium_crypto_secretbox_open(
            $input, $this->options['nonce'], $this->options['key']
        );
    }
}
