<?php declare(strict_types=1);
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-encrypting
 */
namespace froq\encrypting\oneway;

/**
 * A class, able to perform oneway encrypting operations utilizing sodium stuff.
 *
 * @package froq\encrypting\oneway
 * @class   froq\encrypting\oneway\Sodium
 * @author  Kerem Güneş
 * @since   4.0
 */
class Sodium extends Oneway
{
    /**
     * Default operations limit.
     *
     * Although there is no constant that gives 1, seems it is valid. The only existing
     * constants (SODIUM_CRYPTO_PWHASH_OPSLIMIT_*) are giving 2, 3 and 4.
     * @see https://www.php.net/sodium_crypto_pwhash_str
     */
    public const OPS_LIMIT = 1;

    /**
     * Default memory limit.
     *
     * Minimum value of the existing constants (SODIUM_CRYPTO_PWHASH_MEMLIMIT_*) is 67108864
     * bytes (64MB) that I find it too excessive. So 1MB seems enough to create a good password.
     * @see https://www.php.net/sodium_crypto_pwhash_str
     */
    public const MEM_LIMIT = 1024 ** 2; // 1MB

    /**
     * Constructor.
     *
     * @param  array|null $options
     * @throws froq\encrypting\oneway\SodiumException
     */
    public function __construct(array $options = null)
    {
        $options['opslimit'] ??= self::OPS_LIMIT;
        $options['memlimit'] ??= self::MEM_LIMIT;

        static $minMemlimit = 1024 * 8; // 8KB

        if ($options['opslimit'] < 1) {
            throw SodiumException::forInvalidOpsOption();
        }
        if ($options['memlimit'] < $minMemlimit) {
            throw SodiumException::forInvalidMemOption();
        }

        parent::__construct($options);
    }

    /**
     * @inheritDoc froq\encrypting\oneway\Oneway
     */
    public function hash(string $input): string|null
    {
        try {
            return sodium_crypto_pwhash_str(
                $input, $this->options['opslimit'], $this->options['memlimit']
            );
        } catch (\Throwable $e) {
            throw new SodiumException($e, extract: true);
        }
    }

    /**
     * @inheritDoc froq\encrypting\oneway\Oneway
     */
    public function verify(string $input, string $hash): bool
    {
        return (bool) sodium_crypto_pwhash_str_verify($hash, $input);
    }
}
