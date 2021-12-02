<?php
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-encrypting
 */
declare(strict_types=1);

namespace froq\encrypting\oneway;

use froq\encrypting\oneway\{Oneway, OnewayException};
use froq\encrypting\Base;

/**
 * Password.
 *
 * Represents a class entity which is able to perform oneway encrypting operations utilizing password stuff.
 *
 * @package froq\encrypting\oneway
 * @object  froq\encrypting\oneway\Password
 * @author  Kerem Güneş
 * @since   1.0
 */
final class Password extends Oneway
{
    /**
     * Default algo.
     * @const string
     */
    public const ALGO = PASSWORD_DEFAULT;

    /**
     * Default cost.
     * @const int
     */
    public const COST = 9;

    /**
     * Constructor.
     *
     * @param array<string, any|null>|null $options
     */
    public function __construct(array $options = null)
    {
        $options['algo'] ??= self::ALGO;
        $options['cost'] ??= self::COST;

        parent::__construct($options);
    }

    /**
     * @inheritDoc froq\encrypting\oneway\Oneway
     */
    public function hash(string $in): string|null
    {
        $algo    = $this->options['algo'];
        $options = $this->options;

        // Not used in function options.
        unset($options['algo']);

        $hash = password_hash($in, $algo, $options);

        return ($hash !== false) ? $hash : null; // Null=Error.
    }

    /**
     * @inheritDoc froq\encrypting\oneway\Oneway
     */
    public function verify(string $in, string $hash): bool
    {
        return (bool) password_verify($in, $hash);
    }

    /**
     * Generate a password by given length.
     *
     * @param  int  $length
     * @param  bool $puncted
     * @return string
     * @throws froq\encrypting\oneway\OnewayException
     */
    public static final function generate(int $length, bool $puncted = false): string
    {
        if ($length < 2) {
            throw new OnewayException('Invalid length value `%s`, length must be equal or greater'
                . ' than 2', $length);
        }

        return random_string($length, $puncted);
    }
}
