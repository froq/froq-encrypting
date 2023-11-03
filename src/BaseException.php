<?php declare(strict_types=1);
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-encrypting
 */
namespace froq\encrypting;

/**
 * @package froq\encrypting
 * @class   froq\encrypting\BaseException
 * @author  Kerem Güneş
 * @since   6.0
 */
class BaseException extends EncryptingException
{
    public static function forEmptyCharacters(): static
    {
        return new static('Characters cannot be empty');
    }

    public static function forInvalidCharactersLength(int $length): static
    {
        return new static('Characters length must be between 2-256, %s given', $length);
    }

    public static function forInvalidCharacters(string $characters): static
    {
        return new static('Invalid characters %q found in given input', $characters);
    }

    public static function forInvalidBaseArgument(int $base): static
    {
        return new static('Argument $base must be between 2-64, %s given', $base);
    }
}
