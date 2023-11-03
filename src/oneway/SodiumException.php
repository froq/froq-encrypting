<?php declare(strict_types=1);
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-encrypting
 */
namespace froq\encrypting\oneway;

/**
 * @package froq\encrypting\oneway
 * @class   froq\encrypting\oneway\SodiumException
 * @author  Kerem Güneş
 * @since   7.0
 */
class SodiumException extends OnewayException
{
    public static function forInvalidOpsOption(): static
    {
        return new static('Option "opslimit" is too low, minimum value is 1');
    }

    public static function forInvalidMemOption(): static
    {
        return new static('Option "memlimit" is too low, minimum value is 8KB (8192 bytes)');
    }
}
