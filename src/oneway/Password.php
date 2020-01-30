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

use froq\encrypting\oneway\Oneway;

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
     * @const int
     */
    public const ALGO = PASSWORD_DEFAULT;

    /**
     * Cost.
     * @const int
     */
    public const COST = 10;

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
     * @inheritDoc froq\encryption\oneway\Oneway
     */
    public function verify(string $input, string $inputHash): bool
    {
        return password_verify($input, $inputHash);
    }

    /**
     * Generate.
     * @param  int  $length
     * @param  bool $lettersOnly
     * @return string
     */
    public static function generate(int $length = 8, bool $lettersOnly = true): string
    {
        static $anChars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        static $grChars = '!^+%&/\(){}[]<>=*?-_|$#.:,;';

        if ($lettersOnly) {
            return substr(str_shuffle($anChars), 0, $length);
        }

        // 1 graph char for each 3 alpha numeric chars (approximately..).
        $lengthSub = (int) floor($length / 3);

        return str_shuffle(
            substr(str_shuffle($anChars), 0, $length - $lengthSub) .
            substr(str_shuffle($grChars), 0, $lengthSub)
        );
    }
}
