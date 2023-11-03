<?php declare(strict_types=1);
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-encrypting
 */
namespace froq\encrypting;

/**
 * @package froq\encrypting
 * @class   froq\encrypting\SuidException
 * @author  Kerem Güneş
 * @since   6.0
 */
class SuidException extends EncryptingException
{
    public static function forInvalidLengthArgument(int $length): static
    {
        return new static('Argument $length must be greater than 1, %s given', $length);
    }

    public static function forInvalidBaseArgument(int $base): static
    {
        return new static('Argument $base must be between 2-62, %s given', $base);
    }
}
