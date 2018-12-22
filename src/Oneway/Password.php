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

namespace Froq\Encryption\Oneway;

/**
 * @package    Froq
 * @subpackage Froq\Encryption
 * @object     Froq\Encryption\Oneway\Password
 * @author     Kerem Güneş <k-gun@mail.com>
 */
final class Password extends Oneway
{
    /**
     * Algo.
     * @var int
     */
    private $algo = PASSWORD_DEFAULT;

    /**
     * Options.
     * @var array
     */
    private $options = ['cost' => 10];

    /**
     * Constructor.
     * @param string $data
     * @param int    $algo
     * @param array  $options
     */
    public function __construct(string $data, int $algo = null, array $options = [])
    {
        $this->data = $data;
        $this->algo = $algo ?? $this->algo;
        $this->options = array_merge($this->options, $options);
    }

    /**
     * @inheritDoc Froq\Encryption\Oneway\Oneway
     */
    public function hash(): bool
    {
        $this->hash = password_hash($this->data, $this->algo, $this->options);

        return !empty($this->hash);
    }

    /**
     * @inheritDoc Froq\Encryption\Oneway\Oneway
     */
    public function verify(string $hash): bool
    {
        return password_verify($this->data, $hash);
    }
}
