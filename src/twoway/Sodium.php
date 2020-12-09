<?php
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 <https://opensource.org/licenses/apache-2.0>
 */
declare(strict_types=1);

namespace froq\encrypting\twoway;

use froq\encrypting\twoway\{Twoway, TwowayException};
use SodiumException;

/**
 * Sodium.
 *
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
            throw new TwowayException("Invalid key length '%s', minimum key length is 16 (tip: use "
                . "Sodium::generateKey() method to get a strong key)", $keyLength);
        }

        // Key size must be 32-length.
        if ($keyLength != SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            $key = md5($key);
        }

        // Check nonce length.
        if (strlen($nonce) != SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
            throw new TwowayException("Invalid nonce length '%s', nonce length must be '%s'",
                [strlen($nonce), SODIUM_CRYPTO_SECRETBOX_NONCEBYTES]);
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
            $out = sodium_crypto_secretbox($data, $this->nonce, $this->key);
            if ($out !== false) {
                return !$raw ? base64_encode($out) : $out;
            }
        } catch (SodiumException) {}

        return null;
    }

    /**
     * @inheritDoc froq\encrypting\twoway\Twoway
     */
    public function decode(string $data, bool $raw = false): ?string
    {
        $data = !$raw ? base64_decode($data, true) : $data;

        try {
            $out = sodium_crypto_secretbox_open($data, $this->nonce, $this->key);
            if ($out !== false) {
                return $out;
            }
        } catch (SodiumException) {}

        return null;
    }
}
