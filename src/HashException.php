<?php declare(strict_types=1);
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-encrypting
 */
namespace froq\encrypting;

/**
 * @package froq\encrypting
 * @class   froq\encrypting\HashException
 * @author  Kerem Güneş
 * @since   6.0
 */
class HashException extends EncryptingException
{
    public static function forInvalidLength(int $length, array $lengths): static
    {
        return new static('Invalid length %q [valids: %A]', [$length, $lengths]);
    }

    public static function forInvalidAlgo(string $algo, array $algos): static
    {
        return new static('Invalid algo %q [valids: %A]', [$algo, $algos]);
    }
}
