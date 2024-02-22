<?php declare(strict_types=1);
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-encrypting
 */
namespace froq\encrypting;

/**
 * @package froq\encrypting
 * @class   froq\encrypting\CsrfException
 * @author  Kerem Güneş
 * @since   7.2
 */
class CsrfException extends EncryptingException
{
    public static function forNoTokenGivenYet(): static
    {
        return new static('No token given yet, set token before validation');
    }
}
