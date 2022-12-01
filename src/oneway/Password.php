<?php declare(strict_types=1);
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-encrypting
 */
namespace froq\encrypting\oneway;

/**
 * A class, able to perform oneway encrypting operations utilizing password stuff.
 *
 * @package froq\encrypting\oneway
 * @class   froq\encrypting\oneway\Password
 * @author  Kerem Güneş
 * @since   1.0
 */
class Password extends Oneway
{
    /** Default algo. */
    public const ALGO = PASSWORD_DEFAULT;

    /** Default cost. */
    public const COST = 9;

    /**
     * Constructor.
     *
     * @param  array|null $options
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
    public function hash(string $input): string|null
    {
        $ret = password_hash($input, $this->options['algo'], $this->options);

        return ($ret !== false) ? $ret : null;
    }

    /**
     * @inheritDoc froq\encrypting\oneway\Oneway
     */
    public function verify(string $input, string $hash): bool
    {
        return (bool) password_verify($input, $hash);
    }
}
