<?php
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-encrypting
 */
declare(strict_types=1);

namespace froq\encrypting\oneway;

use froq\common\trait\OptionTrait;

/**
 * An abstract class, used in `oneway` package only.
 *
 * @package froq\encrypting\oneway
 * @object  froq\encrypting\oneway\Oneway
 * @author  Kerem Güneş
 * @since   1.0
 */
abstract class Oneway
{
    use OptionTrait;

    /**
     * Constructor.
     *
     * @param  array|null $options
     */
    public function __construct(array $options = null)
    {
        $this->setOptions($options);
    }

    /**
     * Generate a password by given length.
     *
     * @param  int  $length
     * @param  bool $puncted
     * @return string
     * @throws froq\encrypting\oneway\OnewayException
     */
    public static final function generatePassword(int $length, bool $puncted = false): string
    {
        if ($length < 2) {
            throw new OnewayException(
                'Argument $length must be greater than 1, %s given',
                $length
            );
        }

        return random_string($length, $puncted);
    }

    /**
     * Hash given input.
     *
     * @param  string $input
     * @return string|null
     */
    abstract public function hash(string $input): string|null;

    /**
     * Verify given input with given hash.
     *
     * @param  string $input
     * @param  string $hash
     * @return bool
     */
    abstract public function verify(string $input, string $hash): bool;
}
