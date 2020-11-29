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
    protected array $options = [];

    /**
     * Constructor.
     * @param array<string, any|null>|null $options
     */
    public function __construct(array $options = null)
    {
        $this->options = array_merge($this->options, $options ?? []);
    }

    /**
     * Get option.
     * @return array<string, any|null>
     */
    public final function getOptions(): array
    {
        return $this->options;
    }

    /**
     * Hash make.
     * @param  string     $input
     * @param  array|null $options
     * @return ?string
     * @since  4.5
     */
    public static final function make(string $input, array $options = null): ?string
    {
        return (new static($options))->hash($input);
    }

    /**
     * Hash verify.
     * @param  string $input
     * @param  string $inputHash
     * @return bool
     * @since  4.5
     */
    public static final function validate(string $input, string $inputHash): bool
    {
        return (new static())->verify($input, $inputHash);
    }

    /**
     * Hash.
     * @param  string $input
     * @return ?string
     */
    public abstract function hash(string $input): ?string;

    /**
     * Verify.
     * @param  string $input
     * @param  string $inputHash
     * @return bool
     */
    public abstract function verify(string $input, string $inputHash): bool;
}
