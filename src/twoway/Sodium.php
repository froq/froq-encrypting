<?php declare(strict_types=1);
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-encrypting
 */
namespace froq\encrypting\twoway;

/**
 * A class, able to perform twoway encrypting operations utilizing Sodium extension.
 *
 * @package froq\encrypting\twoway
 * @class   froq\encrypting\twoway\Sodium
 * @author  Kerem Güneş
 * @since   3.0
 */
class Sodium extends Twoway
{
    /**
     * Constructor.
     *
     * @param  string     $key
     * @param  string     $nonce
     * @param  array|null $options
     * @throws froq\encrypting\twoway\SodiumException
     */
    public function __construct(string $key, string $nonce, array $options = null)
    {
        if (!extension_loaded('sodium')) {
            throw SodiumException::forNotFoundExtension('sodium');
        }

        parent::checkKeyLength($keyLength = strlen($key));

        // Key length must be 32-length.
        if ($keyLength !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            throw SodiumException::forInvalidKeyLength($keyLength, SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
        }

        // Nonce length must be 32-length.
        if (strlen($nonce) !== SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
            throw SodiumException::forInvalidNonceLength(strlen($nonce), SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
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
