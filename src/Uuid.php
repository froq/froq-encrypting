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
 * @object     Froq\Encryption\Uuid
 * @author     Kerem Güneş <k-gun@mail.com>
 */
final /* static */ class Uuid
{
    /**
     * Types.
     * @const int
     */
    public const TYPE_0       = 0, // simple serial
                 TYPE_4       = 4, // random (UUID/v4)
                 TYPE_DEFAULT = self::TYPE_0;

    /**
     * Generate.
     * @param  int  $type
     * @param  bool $translate
     * @return string
     * @throws Froq\Encryption\EncryptionException
     */
    public static function generate(int $type = null, bool $translate = false): string
    {
        $out = '';
        $type = $type ?? self::TYPE_DEFAULT;

        if ($type == self::TYPE_0) {
            $date = getdate();
            $uniq = preg_split('~([a-f0-9]{8})([a-f0-9]{6})~', uniqid('', true), -1,
                PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
            $rand = bin2hex(random_bytes(3));

            $out = sprintf('%08s-%04x-%04x-%04x-%6s%6s',
                $uniq[0], $date['year'], $date['mon'], $date['mday'], $uniq[1], $rand);
        } else if ($type == self::TYPE_4) {
            $rand = random_bytes(16);
            $rand[6] = chr(ord($rand[6]) & 0x0f | 0x40);
            $rand[8] = chr(ord($rand[8]) & 0x3f | 0x80);

            $out = vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($rand), 4));
        }

        // valid type
        if ($out != '') {
            if ($translate) {
                $out = str_replace('-', '', $out);
            }
            return $out;
        }

        throw new EncryptionException("Given '{$type}' not implemented, '0,4' are accepted!");
    }
}
