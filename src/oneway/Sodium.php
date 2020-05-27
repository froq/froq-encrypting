<?php
/**
 * MIT License <https://opensource.org/licenses/mit>
 *
 * Copyright (c) 2015 Kerem Güneş
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is furnished
 * to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
declare(strict_types=1);

namespace froq\crypto\oneway;

use froq\crypto\oneway\{Oneway, OnewayException};
use SodiumException;

/**
 * Sodium.
 * @package froq\crypto\oneway
 * @object  froq\crypto\oneway\Sodium
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
     * @throws froq\crypto\oneway\OnewayException
     */
    public function __construct(array $options = null)
    {
        $options['opslimit'] ??= self::OPERATION_LIMIT;
        $options['memlimit'] ??= self::MEMORY_LIMIT;

        static $minMemlimit = 1024 * 8; // 8KB

        if ($options['opslimit'] < 1) {
            throw new OnewayException('Option "opslimit" is to low, minimum value is 1');
        }
        if ($options['memlimit'] < $minMemlimit) {
            throw new OnewayException('Option "memlimit" is to low, minimum value is 8KB '.
                '(8192 bytes)');
        }

        parent::__construct($options);
    }

    /**
     * @inheritDoc froq\crypto\oneway\Oneway
     */
    public function hash(string $input): ?string
    {
        $inputHash = false;

        // In case any other Sodium errors happen.
        try {
            $inputHash =@ sodium_crypto_pwhash_str(
                $input, $this->options['opslimit'], $this->options['memlimit']
            );
        } catch (SodiumException $e) {}

        return ($inputHash !== false) ? $inputHash : null; // Null=Error.
    }

    /**
     * @inheritDoc froq\crypto\oneway\Oneway
     */
    public function verify(string $input, string $inputHash): bool
    {
        return sodium_crypto_pwhash_str_verify($inputHash, $input);
    }
}
