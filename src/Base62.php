<?php
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-encrypting
 */
declare(strict_types=1);

namespace froq\encrypting;

/**
 * Base 62.
 *
 * Represents a static class which provides a Base-62 encoding/decoding methods.
 *
 * @package froq\encrypting
 * @object  froq\encrypting\Base62
 * @author  Kerem Güneş
 * @since   5.0
 * @static
 */
final class Base62
{
    /**
     * Encode given input as given base.
     *
     * @param  string $in
     * @param  int    $base
     * @param  bool   $bin
     * @return string
     */
    public static function encode(string $in, int $base, bool $bin = false): string
    {
        $bin && $in = bin2hex($in);

        return (string) convert_base($in, $base, 62);
    }

    /**
     * Decode given input as given base.
     *
     * @param  string $in
     * @param  int    $base
     * @param  bool   $bin
     * @return string
     */
    public static function decode(string $in, int $base, bool $bin = false): string
    {
        $in = (string) convert_base($in, 62, $base);

        $bin && $in = hex2bin($in);

        return $in;
    }
}
