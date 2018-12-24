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

namespace Froq\Encryption;

/**
 * @package    Froq
 * @subpackage Froq\Encryption
 * @object     Froq\Encryption\Salt
 * @author     Kerem Güneş <k-gun@mail.com>
 */
final /* static */ class Salt
{
    /**
     * Length.
     * @const int
     */
    public const LENGTH = 128;

    /**
     * Characters.
     * @const string
     */
    public const CHARACTERS = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/';

    /**
     * Generate.
     * @param  int  $length
     * @param  bool $translate
     * @return string
     * @see    https://github.com/php/php-src/blob/master/ext/session/session.c#L267,#L326
     */
    public static function generate(int $length = null, bool $translate = false): string
    {
        $len = $length ?? self::LENGTH; // output length
        $bpc = 6; // bits per character

        $randomBytes = random_bytes((int) ceil($len * $bpc / 8));

        $p = 0; $q = strlen($randomBytes);
        $w = 0; $have = 0; $mask = (1 << $bpc) - 1;
        $out = '';

        while ($len--) {
            if ($have < $bpc) {
                if ($p < $q) {
                    $byte = ord($randomBytes[$p++]);
                    $w |= ($byte << $have);
                    $have += 8;
                } else {
                    break;
                }
            }
            $out .= self::CHARACTERS[$w & $mask];
            $w >>= $bpc;
            $have -= $bpc;
        }

        if ($translate) {
            $out = strtr($out, '+/', '-_');
        }

        return $out;
    }
}
