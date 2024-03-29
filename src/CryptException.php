<?php declare(strict_types=1);
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-encrypting
 */
namespace froq\encrypting;

/**
 * @package froq\encrypting
 * @class   froq\encrypting\CryptException
 * @author  Kerem Güneş
 * @since   6.0
 */
class CryptException extends EncryptingException
{
    public static function forInvalidSecretArgument(string $secret): static
    {
        return new static(
            'Argument $secret length must be %s [given length: %s]',
            [Crypt::SECRET_LENGTH, strlen($secret)]
        );
    }

    public static function forInvalidEncdecArgument(int $encdec): static
    {
        return new static('Argument $encdec must be between 2-62, %s given', $encdec);
    }
}
