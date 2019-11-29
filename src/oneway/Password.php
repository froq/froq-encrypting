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

namespace froq\encryption\oneway;

use froq\encryption\oneway\Oneway;

/**
 * Password.
 * @package froq\encryption\oneway
 * @object  froq\encryption\oneway\Password
 * @author  Kerem Güneş <k-gun@mail.com>
 * @since   1.0
 */
final class Password extends Oneway
{
    /**
     * Algo.
     * @var string
     */
    private string $algo = PASSWORD_BCRYPT;

    /**
     * Options.
     * @var array
     */
    private array $options = ['cost' => 10];

    /**
     * Constructor.
     * @param string|null $algo
     * @param array|null  $options
     */
    public function __construct(string $algo = null, array $options = null)
    {
        $this->algo = $algo ?? $this->algo;
        $this->options = array_merge($this->options, $options ?? []);
    }

    /**
     * Get algo.
     * @return string
     */
    public function getAlgo(): string
    {
        return $this->algo;
    }

    /**
     * Get option.
     * @return array
     */
    public function getOptions(): array
    {
        return $this->options;
    }

    /**
     * @inheritDoc froq\encryption\oneway\Oneway
     */
    public function hash(string $input): string
    {
        return (string) password_hash($input, $this->algo, $this->options);
    }

    /**
     * @inheritDoc froq\encryption\oneway\Oneway
     */
    public function verify(string $input, string $inputHash): bool
    {
        return (bool) password_verify($input, $inputHash);
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
              substr(str_shuffle($anChars), 0, $length - $lengthSub)
            . substr(str_shuffle($grChars), 0, $lengthSub)
        );
    }
}
