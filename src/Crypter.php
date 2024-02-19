<?php declare(strict_types=1);
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-encrypting
 */
namespace froq\encrypting;

/**
 * A class, provides encrypt/decrypt operations using `Crypt` class in OOP-way.
 *
 * @package froq\encrypting
 * @class   froq\encrypting\Crypter
 * @author  Kerem Güneş
 * @since   6.0
 */
class Crypter
{
    /**
     * Constructor.
     *
     * @param string $passphrase
     */
    public function __construct(
        public readonly string $passphrase
    ) {}

    /**
     * Encrypt given non-encrypted input.
     *
     * @param  string   $input
     * @param  bool|int $encode
     * @return string
     */
    public function encrypt(string $input, bool|int $encode = false): string
    {
        return Crypt::encrypt($input, $this->passphrase, $encode);
    }

    /**
     * Decrypt given encrypted input.
     *
     * @param  string   $input
     * @param  bool|int $decode
     * @return string
     */
    public function decrypt(string $input, bool|int $decode = false): string
    {
        return Crypt::decrypt($input, $this->passphrase, $decode);
    }
}
