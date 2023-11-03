<?php declare(strict_types=1);
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-encrypting
 */
namespace froq\encrypting\twoway;

/**
 * @package froq\encrypting\twoway
 * @class   froq\encrypting\twoway\OpenSslException
 * @author  Kerem Güneş
 * @since   7.0
 */
class OpenSslException extends TwowayException
{
    public static function forInvalidCipherMethod(string $method): static
    {
        return new static('Invalid cipher method %q', $method);
    }
}
