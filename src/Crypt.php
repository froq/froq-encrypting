<?php declare(strict_types=1);
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-encrypting
 */
namespace froq\encrypting;

/**
 * A static class, provides encrypt/decrypt operations with "aes-256-ctr" cipher method
 * as default using OpenSSL utilities if exists, or Sodium library.
 *
 * Original source: https://stackoverflow.com/a/2448441/362780
 *
 * @package froq\encrypting
 * @class   froq\encrypting\Crypt
 * @author  Kerem Güneş
 * @since   6.0
 * @static
 */
class Crypt
{
    /**
     * Secret length (OpenSSL: 40 is passphrase, 16 is initialization vector,
     * Sodium: 32 is key, 24 nonce). */
    public final const SECRET_LENGTH = 56;

    /** Default cipher method (OpenSSL only). */
    public final const CIPHER_METHOD = 'aes-256-ctr';

    /**
     * Encrypt given non-encrypted input.
     *
     * @param  string   $input
     * @param  string   $secret
     * @param  bool|int $encode True for Base-62, int for any base.
     * @return string
     * @throws froq\encrypting\CryptException
     */
    public static function encrypt(string $input, string $secret, bool|int $encode = false): string
    {
        if (strlen($secret) !== self::SECRET_LENGTH) {
            throw CryptException::forInvalidSecretArgument($secret);
        }

        if (extension_loaded('openssl')) {
            [$pp, $iv] = str_chunk($secret, 40, false);
            $ret = openssl_encrypt($input, 'aes-256-ctr', $pp, iv: $iv);
        } else {
            [$key, $nonce] = str_chunk($secret, 32, false);
            $ret = (new twoway\Sodium($key, $nonce))->encrypt($input);
        }

        return ($encode === false) ? $ret : Base::encode($ret, ($encode === true ? 62 : $encode));
    }

    /**
     * Decrypt given encrypted input.
     *
     * @param  string   $input
     * @param  string   $secret
     * @param  bool|int $decode True for Base-62, int for any base.
     * @return string
     * @throws froq\encrypting\CryptException
     */
    public static function decrypt(string $input, string $secret, bool|int $decode = false): string
    {
        if (strlen($secret) !== self::SECRET_LENGTH) {
            throw CryptException::forInvalidSecretArgument($secret);
        }

        $ret = ($decode === false) ? $input : Base::decode($input, ($decode === true ? 62 : $decode));

        if (extension_loaded('openssl')) {
            [$pp, $iv] = str_chunk($secret, 40, false);
            $ret = openssl_decrypt($ret, 'aes-256-ctr', $pp, iv: $iv);
        } else {
            [$key, $nonce] = str_chunk($secret, 32, false);
            $ret = (new twoway\Sodium($key, $nonce))->decrypt($ret);
        }

        return $ret;
    }
}
