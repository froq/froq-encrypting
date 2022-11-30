<?php
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-encrypting
 */
declare(strict_types=1);

namespace froq\encrypting\oneway;

/**
 * A class, able to perform oneway encrypting operations utilizing sodium stuff.
 *
 * @package froq\encrypting\oneway
 * @object  froq\encrypting\oneway\Sodium
 * @author  Kerem Güneş
 * @since   4.0
 */
class Sodium extends Oneway
{
    /**
     * Operations limit.
     *
     * Although there is no constant that gives 1, seems it is valid. The only existing
     * constants (SODIUM_CRYPTO_PWHASH_OPSLIMIT_*) are giving 2, 3 and 4.
     * @see https://www.php.net/sodium_crypto_pwhash_str
     *
     * @const int
     */
    public const OPS_LIMIT = 1;

    /**
     * Memory limit.
     *
     * Minimum value of the existing constants (SODIUM_CRYPTO_PWHASH_MEMLIMIT_*) is 67108864
     * bytes (64MB) that I find it too excessive. So 1MB seems enough to create a good password.
     * @see https://www.php.net/sodium_crypto_pwhash_str
     *
     * @const int
     */
    public const MEM_LIMIT = 1024 ** 2; // 1MB

    /**
     * Constructor.
     *
     * @param  array|null $options
     * @throws froq\encrypting\oneway\OnewayException
     */
    public function __construct(array $options = null)
    {
        $options['opslimit'] ??= self::OPS_LIMIT;
        $options['memlimit'] ??= self::MEM_LIMIT;

        static $minMemlimit = 1024 * 8; // 8KB

        if ($options['opslimit'] < 1) {
            throw new OnewayException('Option "opslimit" is too low, minimum value is 1');
        }
        if ($options['memlimit'] < $minMemlimit) {
            throw new OnewayException('Option "memlimit" is too low, minimum value is 8KB (8192 bytes)');
        }

        parent::__construct($options);
    }

    /**
     * @inheritDoc froq\encrypting\oneway\Oneway
     */
    public function hash(string $input): string|null
    {
        $ret = sodium_crypto_pwhash_str(
            $input, $this->options['opslimit'], $this->options['memlimit']
        );

        return ($ret !== false) ? $ret : null;
    }

    /**
     * @inheritDoc froq\encrypting\oneway\Oneway
     */
    public function verify(string $input, string $hash): bool
    {
        return (bool) sodium_crypto_pwhash_str_verify($hash, $input);
    }
}
