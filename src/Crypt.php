<?php declare(strict_types=1);
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-encrypting
 */
namespace froq\encrypting;

/**
 * A static class, provides encrypt/decrypt operations with "aes-256-ctr" cipher method
 * as default using OpenSSL utilities.
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
    /** Default cipher method. */
    public const CIPHER_METHOD = 'aes-256-ctr';

    /**
     * Encrypt given non-encrypted input with given passphrase & initialization vector.
     *
     * @param  string $input
     * @param  string $pp     The passphrase (key).
     * @param  string $iv     The initialization vector.
     * @param  bool   $encode
     * @return string
     * @throws froq\encrypting\CryptException
     */
    public static function encrypt(string $input, string $pp, string $iv, bool $encode = false): string
    {
        if (strlen($iv) !== 16) {
            throw CryptException::forInvalidIvArgument(strlen($iv));
        }

        $ret = openssl_encrypt($input, static::CIPHER_METHOD, $pp, iv: $iv);

        return $encode ? Base62::encode($ret) : $ret;
    }

    /**
     * Decrypt given encrypted input with given passphrase & initialization vector.
     *
     * @param  string $input
     * @param  string $pp     The passphrase (key).
     * @param  string $iv     The initialization vector.
     * @param  bool   $decode
     * @return string
     * @throws froq\encrypting\CryptException
     */
    public static function decrypt(string $input, string $pp, string $iv, bool $decode = false): string
    {
        if (strlen($iv) !== 16) {
            throw CryptException::forInvalidIvArgument(strlen($iv));
        }

        $ret = $decode ? Base62::decode($input) : $input;

        return openssl_decrypt($ret, static::CIPHER_METHOD, $pp, iv: $iv);
    }
}
