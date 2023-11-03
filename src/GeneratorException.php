<?php declare(strict_types=1);
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-encrypting
 */
namespace froq\encrypting;

/**
 * @package froq\encrypting
 * @class   froq\encrypting\GeneratorException
 * @author  Kerem Güneş
 * @since   6.0
 */
class GeneratorException extends EncryptingException
{
    public static function forMinimumLengthArgument(int $minimum, int $length): static
    {
        return new static('Argument $length must be minimun %s, %s given', [$minimum, $length]);
    }

    public static function forInvalidBaseArgument(int $base): static
    {
        return new static('Argument $base must be between 10-62, %s given', $base);
    }
}
