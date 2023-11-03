<?php declare(strict_types=1);
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-encrypting
 */
namespace froq\encrypting;

/**
 * @package froq\encrypting
 * @class   froq\encrypting\UuidException
 * @author  Kerem Güneş
 * @since   6.0
 */
class UuidException extends EncryptingException
{
    public static function forInvalidHashLengthToFormat(): static
    {
        return new static('Format option for only 32-length hashes');
    }

    public static function forInvalidInputToFormat(): static
    {
        return new static('Input must be a 32-length x-digit to format');
    }
}
