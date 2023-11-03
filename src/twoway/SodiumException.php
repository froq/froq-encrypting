<?php declare(strict_types=1);
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-encrypting
 */
namespace froq\encrypting\twoway;

/**
 * @package froq\encrypting\twoway
 * @class   froq\encrypting\twoway\SodiumException
 * @author  Kerem Güneş
 * @since   7.0
 */
class SodiumException extends TwowayException
{
    public static function forInvalidKeyLength(int $length, int $lengthMust): static
    {
        return new static('Invalid key length %s, key length must be %s', [$length, $lengthMust]);
    }

    public static function forInvalidNonceLength(int $length, int $lengthMust): static
    {
        return new static('Invalid nonce length %s, nonce length must be %s', [$length, $lengthMust]);
    }
}
