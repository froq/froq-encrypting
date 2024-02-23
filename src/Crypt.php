<?php declare(strict_types=1);
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-encrypting
 */
namespace froq\encrypting;

/**
 * A class, provides encrypt/decrypt operations with "aes-256-ctr" cipher method
 * as default using OpenSSL utilities if exists, or Sodium library.
 *
 * Original source: https://stackoverflow.com/a/2448441/362780
 *
 * @package froq\encrypting
 * @class   froq\encrypting\Crypt
 * @author  Kerem Güneş
 * @since   6.0
 */
class Crypt
{
    /**
     * Secret length (40 is passphrase - 16 is initialization vector for OpenSSL,
     * 32 is key - 24 nonce for Sodium). */
    public final const SECRET_LENGTH = 56;

    /** Default cipher method (OpenSSL only). */
    public final const CIPHER_METHOD = 'aes-256-ctr';

    /**
     * Constructor.
     *
     * @param  string   $secret
     * @param  bool|int $encdec True for Base-62, int for any base between 2-62.
     * @throws froq\encrypting\CryptException
     */
    public function __construct(
        public readonly string $secret,
        public readonly bool|int $encdec = false
    ) {
        if (strlen($this->secret) !== self::SECRET_LENGTH) {
            throw CryptException::forInvalidSecretArgument($this->secret);
        }

        // Validate given base as encdec option.
        if (is_int($this->encdec) && ($this->encdec < 2 || $this->encdec > 62)) {
            throw CryptException::forInvalidEncdecArgument($this->encdec);
        }
    }

    /**
     * Encrypt a non-encrypted input.
     *
     * @param  string $input
     * @return string
     * @throws froq\encrypting\CryptException
     */
    public function encrypt(string $input): string
    {
        try {
            if (extension_loaded('openssl')) {
                [$pp, $iv] = str_chunk($this->secret, 40, false);
                $ret = openssl_encrypt($input, self::CIPHER_METHOD, $pp, iv: $iv);
            } else {
                [$key, $nonce] = str_chunk($this->secret, 32, false);
                $ret = (new twoway\Sodium($key, $nonce))->encrypt($input);
            }

            $ret = ($this->encdec === false) ? $ret
                 : Base::encode($ret, ($this->encdec === true ? 62 : $this->encdec));

            return $ret;
        } catch (BaseException $e) {
            throw new CryptException($e);
        }
    }

    /**
     * Decrypt an encrypted input.
     *
     * @param  string $input
     * @return string
     * @throws froq\encrypting\CryptException
     */
    public function decrypt(string $input): string
    {
        try {
            $ret = ($this->encdec === false) ? $input
                 : Base::decode($input, ($this->encdec === true ? 62 : $this->encdec));

            if (extension_loaded('openssl')) {
                [$pp, $iv] = str_chunk($this->secret, 40, false);
                $ret = openssl_decrypt($ret, self::CIPHER_METHOD, $pp, iv: $iv);
            } else {
                [$key, $nonce] = str_chunk($this->secret, 32, false);
                $ret = (new twoway\Sodium($key, $nonce))->decrypt($ret);
            }

            return $ret;
        } catch (BaseException $e) {
            throw new CryptException($e);
        }
    }
}
