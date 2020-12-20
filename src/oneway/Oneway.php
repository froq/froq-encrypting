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
 * @package froq\encrypting\oneway
 * @object  froq\encrypting\oneway\Oneway
 * @author  Kerem Güneş <k-gun@mail.com>
 * @since   1.0
 */
abstract class Oneway
{
    /**
     * Options.
     * @var array<string, any|null>
     */
    protected array $options;

    /**
     * Constructor.
     * @param array<string, any|null>|null $options
     */
    public function __construct(array $options = null)
    {
        $this->options = $options ?? [];
    }

    /**
     * Get option.
     * @return array<string, any|null>
     */
    public final function options(): array
    {
        return $this->options;
    }

    /**
     * Hash make.
     * @param  string     $in
     * @param  array|null $options
     * @return ?string
     * @since  4.5
     */
    public static final function make(string $in, array $options = null): ?string
    {
        return (new static($options))->hash($in);
    }

    /**
     * Hash verify.
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
     * Hash.
     * @param  string $in
     * @return ?string
     */
    public abstract function hash(string $in): ?string;

    /**
     * Verify.
     * @param  string $in
     * @param  string $hash
     * @return bool
     */
    public abstract function verify(string $in, string $hash): bool;
}
