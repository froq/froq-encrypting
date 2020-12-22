<?php
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 <https://opensource.org/licenses/apache-2.0>
 */
declare(strict_types=1);

namespace froq\encrypting\oneway;

/**
 * Oneway.
 *
 * Represents a abstract class entity that used in `oneway` package only, and also provided make/validate
 * methods as shortcut for hash/verify methods of extender classes.
 *
 * @package froq\encrypting\oneway
 * @object  froq\encrypting\oneway\Oneway
 * @author  Kerem Güneş <k-gun@mail.com>
 * @since   1.0
 */
abstract class Oneway
{
    /** @var array<string, any|null> */
    protected array $options;

    /**
     * Constructor.
     *
     * @param array<string, any|null>|null $options
     */
    public function __construct(array $options = null)
    {
        $this->options = $options ?? [];
    }

    /**
     * Get options property.
     *
     * @return array<string, any|null>
     */
    public final function options(): array
    {
        return $this->options;
    }

    /**
     * Make a hash.
     *
     * @param  string     $in
     * @param  array|null $options
     * @return string|null
     * @since  4.5
     */
    public static final function make(string $in, array $options = null): string|null
    {
        return (new static($options))->hash($in);
    }

    /**
     * Verify a hash.
     *
     * @param  string $in
     * @param  string $hash
     * @return bool
     * @since  4.5
     */
    public static final function validate(string $in, string $hash): bool
    {
        return (new static)->verify($in, $hash);
    }

    /**
     * Hash given input.
     *
     * @param  string $in
     * @return string|null
     */
    abstract public function hash(string $in): string|null;

    /**
     * Verify given input with given hash.
     *
     * @param  string $in
     * @param  string $hash
     * @return bool
     */
    abstract public function verify(string $in, string $hash): bool;
}
