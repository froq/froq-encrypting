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
     * @param  string $input
     * @param  int    $base
     * @param  bool   $bin
     * @return string
     */
    public static function encode(string $input, int $base, bool $bin = false): string
    {
        $bin && $input = bin2hex($input);

        return (string) convert_base($input, $base, 62);
    }

    /**
     * Decode given input as given base.
     *
     * @param  string $input
     * @param  int    $base
     * @param  bool   $bin
     * @return string
     */
    public static function decode(string $input, int $base, bool $bin = false): string
    {
        $input = (string) convert_base($input, 62, $base);

        if ($bin) {
            // Fix: "Hexadecimal input string must have an even length .." error.
            if (strlen($input) % 2) {
                $input .= '0';
            }

            $input = hex2bin($input);
        }

        return $input;
    }
}
