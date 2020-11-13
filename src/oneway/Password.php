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

namespace froq\encrypting\oneway;

use froq\encrypting\oneway\{Oneway, OnewayException};
use froq\encrypting\Base;

/**
 * Password.
 * @package froq\encrypting\oneway
 * @object  froq\encrypting\oneway\Password
 * @author  Kerem Güneş <k-gun@mail.com>
 * @since   1.0
 */
final class Password extends Oneway
{
    /**
     * Algo.
     * @const string
     */
    public const ALGO = PASSWORD_DEFAULT;

    /**
     * Cost.
     * @const int
     */
    public const COST = 9;

    /**
     * Constructor.
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
    public function hash(string $input): ?string
    {
        $algo    = $this->options['algo'];
        $options = $this->options;

        // Not used in function options.
        unset($options['algo']);

        $inputHash =@ password_hash($input, $algo, $options);

        return ($inputHash !== false) ? $inputHash : null; // Null=Error.
    }

    /**
     * @inheritDoc froq\encrypting\oneway\Oneway
     */
    public function verify(string $input, string $inputHash): bool
    {
        return (bool) password_verify($input, $inputHash);
    }

    /**
     * Generate.
     * @param  int  $length
     * @param  bool $puncted
     * @return string
     * @throws froq\encrypting\oneway\OnewayException
     */
    public static final function generate(int $length, bool $puncted = false): string
    {
        if ($length < 2) {
            throw new OnewayException('Invalid length value "%s" given, length must be equal or '.
                'greater than 2', [$length]);
        }

        $chars = Base::ALL_CHARS;
        if ($puncted) { // Add punctuation chars.
            $chars .= '!^+%&/\(){}[]<>=*?-_|$#.:,;';
        }
        $charsLength = strlen($chars);

        $ret = '';

        while (strlen($ret) < $length) {
            $ret .= $chars[mt_rand(0, $charsLength - 1)];
        }

        return $ret;
    }
}
