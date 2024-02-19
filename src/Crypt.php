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
     * Encrypt given non-encrypted input with given passphrase.
     *
     * @param  string   $input
     * @param  string   $passphrase
     * @param  bool|int $encode True for Base-62, int for any base.
     * @return string
     * @throws froq\encrypting\CryptException
     */
    public static function encrypt(string $input, string $passphrase, bool|int $encode = false): string
    {
        if (strlen($passphrase) !== 56) {
            throw CryptException::forInvalidPassphraseArgument(strlen($passphrase));
        }

        if (function_exists('openssl_encrypt')) {
            [$pp, $iv] = str_chunk($passphrase, 40, false);
            $ret = openssl_encrypt($input, 'aes-256-ctr', $pp, iv: $iv);
        } else {
            [$key, $nonce] = str_chunk($passphrase, 32, false);
            $ret = (new twoway\Sodium($key, $nonce))->encrypt($input);
        }

        return ($encode === false) ? $ret : Base::encode($ret, ($encode === true ? 62 : $encode));
    }

    /**
     * Decrypt given encrypted input with given passphrase.
     *
     * @param  string   $input
     * @param  string   $passphrase
     * @param  bool|int $decode True for Base-62, int for any base.
     * @return string
     * @throws froq\encrypting\CryptException
     */
    public static function decrypt(string $input, string $passphrase, bool|int $decode = false): string
    {
        if (strlen($passphrase) !== 56) {
            throw CryptException::forInvalidPassphraseArgument(strlen($passphrase));
        }

        $ret = ($decode === false) ? $input : Base::decode($input, ($decode === true ? 62 : $decode));

        if (function_exists('openssl_encrypt')) {
            [$pp, $iv] = str_chunk($passphrase, 40, false);
            $ret = openssl_decrypt($ret, 'aes-256-ctr', $pp, iv: $iv);
        } else {
            [$key, $nonce] = str_chunk($passphrase, 32, false);
            $ret = (new twoway\Sodium($key, $nonce))->decrypt($ret);
        }

        return $ret;
    }
}
