<?php declare(strict_types=1);
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-encrypting
 */
namespace froq\encrypting\oneway;

use froq\common\trait\OptionTrait;

/**
 * Base class of `oneway`classes.
 *
 * @package froq\encrypting\oneway
 * @class   froq\encrypting\oneway\Oneway
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
     * Hash given input.
     *
     * @param  string $input
     * @return string|null
     */
    public abstract function hash(string $input): string|null;

    /**
     * Verify given input with given hash.
     *
     * @param  string $input
     * @param  string $hash
     * @return bool
     */
    public abstract function verify(string $input, string $hash): bool;
}
