<?php
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 <https://opensource.org/licenses/apache-2.0>
 */
declare(strict_types=1);

namespace froq\encrypting\oneway;

use froq\encrypting\oneway\{Oneway, OnewayException};
use SodiumException;

/**
 * Sodium.
 *
 * @package froq\encrypting\oneway
 * @object  froq\encrypting\oneway\Sodium
 * @author  Kerem Güneş <k-gun@mail.com>
 * @since   4.0
 */
final class Sodium extends Oneway
{
    /**
     * Operation limit.
     *
     * Although there is no constant that gives 1, seems it is valid. The only existing
     * constants (SODIUM_CRYPTO_PWHASH_OPSLIMIT_*) are giving 2, 3 and 4.
     * @see https://www.php.net/sodium_crypto_pwhash_str
     *
     * @const int
     */
    public const OPERATION_LIMIT = 1;

    /**
     * Memory limit.
     *
     * Minimum value of the existing constants (SODIUM_CRYPTO_PWHASH_MEMLIMIT_*) is 67108864
     * bytes (64MB) that I find it too excessive. So 1MB seems enough to create a good password.
     * @see https://www.php.net/sodium_crypto_pwhash_str
     *
     * @const int
     */
    public const MEMORY_LIMIT = 1024 ** 2; // 1MB;

    /**
     * Constructor.
     * @param  array<string, any|null>|null $options
     * @throws froq\encrypting\oneway\OnewayException
     */
    public function __construct(array $options = null)
    {
        $options['opslimit'] ??= self::OPERATION_LIMIT;
        $options['memlimit'] ??= self::MEMORY_LIMIT;

        static $minMemlimit = 1024 * 8; // 8KB

        if ($options['opslimit'] < 1) {
            throw new OnewayException("Option 'opslimit' is too low, minimum value is 1");
        }
        if ($options['memlimit'] < $minMemlimit) {
            throw new OnewayException("Option 'memlimit' is too low, minimum value is 8KB (8192 bytes)");
        }

        parent::__construct($options);
    }

    /**
     * @inheritDoc froq\encrypting\oneway\Oneway
     */
    public function hash(string $in): ?string
    {
        $hash = false;

        try { // In case any other Sodium errors happen.
            $hash = sodium_crypto_pwhash_str(
                $in, $this->options['opslimit'], $this->options['memlimit']
            );
        } catch (SodiumException) {}

        return ($hash !== false) ? $hash : null; // Null=Error.
    }

    /**
     * @inheritDoc froq\encrypting\oneway\Oneway
     */
    public function verify(string $in, string $hash): bool
    {
        return (bool) sodium_crypto_pwhash_str_verify($hash, $in);
    }
}
