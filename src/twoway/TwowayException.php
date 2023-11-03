<?php declare(strict_types=1);
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-encrypting
 */
namespace froq\encrypting\twoway;

/**
 * @package froq\encrypting\twoway
 * @class   froq\encrypting\twoway\TwowayException
 * @author  Kerem Güneş
 * @since   4.0
 */
class TwowayException extends \froq\encrypting\EncryptingException
{
    public static function forNotFoundExtension(string $name): static
    {
        return new static('Extension %q not found', $name);
    }

    public static function forMinimumKeyLength(string $class, int $length, int $lengthMinimum): static
    {
        $exception = self::getExceptionClass($class);

        return new $exception(
            'Invalid key length %s, minimum key length is %s [tip: use %s::generateKey() method to get a key]',
            [$length, $lengthMinimum, $class]
        );
    }

    public static function forInvalidConvertOption(string $class, mixed $option): static
    {
        $exception = self::getExceptionClass($class);

        return new $exception(
            'Option convert must be %A or be between 2-64, %s given',
            [['hex', 'base62', 'base64', 'base64url'], $option]
        );
    }

    /**
     * Get a generic exception class.
     */
    private static function getExceptionClass(string $class): string
    {
        return match (true) {
            $class === Cryptee::class => CrypteeException::class,
            $class === OpenSsl::class => OpenSslException::class,
            $class === Sodium::class  => SodiumException::class
        };
    }
}
