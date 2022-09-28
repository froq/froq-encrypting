<?php
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-encrypting
 */
declare(strict_types=1);

namespace froq\encrypting;

/**
 * A static class, provides encrypt/decrypt operations with "aes-256-ctr" cipher method
 * using OpenSSL utilities.
 *
 * Original source: https://stackoverflow.com/a/2448441/362780
 *
 * @package froq\encrypting
 * @object  froq\encrypting\Crypt
 * @author  Kerem Güneş
 * @since   6.0
 * @static
 */
final class Crypt
{
    /** @const string */
    public const CIPHER_METHOD = 'aes-256-ctr';

    /**
     * Encrypt given non-encrypted input with given passphrase & initialization vector.
     *
     * @param  string $input
     * @param  string $pp
     * @param  string $iv
     * @param  bool   $encode
     * @return string
     * @throws froq\encrypting\CryptException
     */
    public static function encrypt(string $input, string $pp, string $iv, bool $encode = false): string
    {
        if (strlen($iv) != 16) {
            throw new CryptException(
                'Argument $iv length must be 16 [given iv length: %s]',
                strlen($iv)
            );
        }

        $ret = openssl_encrypt($input, self::CIPHER_METHOD, $pp, iv: $iv);

        return $encode ? Base62::encode($ret) : $ret;
    }

    /**
     * Decrypt given encrypted input with given passphrase & initialization vector.
     *
     * @param  string $input
     * @param  string $pp
     * @param  string $iv
     * @param  bool   $decode
     * @return string
     * @throws froq\encrypting\CryptException
     */
    public static function decrypt(string $input, string $pp, string $iv, bool $decode = false): string
    {
        if (strlen($iv) != 16) {
            throw new CryptException(
                'Argument $iv length must be 16 [given iv length: %s]',
                strlen($iv)
            );
        }

        $ret = $decode ? Base62::decode($input) : $input;

        return openssl_decrypt($ret, self::CIPHER_METHOD, $pp, iv: $iv);
    }
}
