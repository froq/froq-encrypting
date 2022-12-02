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
    public static function forInvalidIvArgument(int $length): static
    {
        return new static('Argument $iv length must be 16 [given iv length: %s]', $length);
    }
}
