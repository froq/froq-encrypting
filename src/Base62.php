<?php declare(strict_types=1);
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-encrypting
 */
namespace froq\encrypting;

/**
 * A static class, provides a Base-62 encoding/decoding methods.
 *
 * @package froq\encrypting
 * @class   froq\encrypting\Base62
 * @author  Kerem Güneş
 * @since   5.0
 * @static
 */
class Base62
{
    /**
     * Encode given input.
     *
     * @param  string $input
     * @param  bool   $bin
     * @return string
     */
    public static function encode(string $input, bool $bin = false): string
    {
        $bin && $input = bin2hex($input);

        return Base::encode($input);
    }

    /**
     * Decode given input.
     *
     * @param  string $input
     * @param  bool   $bin
     * @return string
     */
    public static function decode(string $input, bool $bin = false): string
    {
        $input = Base::decode($input);

        $bin && $input = hex2bin($input);

        return $input;
    }
}
