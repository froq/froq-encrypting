<?php
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-encrypting
 */
declare(strict_types=1);

namespace froq\encrypting;

/**
 * Crypter.
 *
 * A crypt class, provides encrypt/decrypt operations using Crypt class in OOP-way.
 *
 * @package froq\encrypting
 * @object  froq\encrypting\Crypter
 * @author  Kerem Güneş
 * @since   6.0
 */
class Crypter
{
    /**
     * Constructor.
     *
     * @param string $key
     * @param string $iv
     */
    public function __construct(
        private string $key,
        private string $iv
    ) {}

    /**
     * Encrypt given non-encrypted input.
     *
     * @param  string $input
     * @param  bool   $encode
     * @return string
     */
    public function encrypt(string $input, bool $encode = false): string
    {
        return Crypt::encrypt($input, $this->key, $this->iv, $encode);
    }

    /**
     * Decrypt given encrypted input.
     *
     * @param  string $input
     * @param  bool   $decode
     * @return string
     */
    public function decrypt(string $input, bool $decode = false): string
    {
        return Crypt::decrypt($input, $this->key, $this->iv, $decode);
    }
}
