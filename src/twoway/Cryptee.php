<?php declare(strict_types=1);
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-encrypting
 */
namespace froq\encrypting\twoway;

/**
 * A class, able to perform twoway encrypting operations utilizing XOR way.
 * Original source: https://github.com/okerem/cryptee
 *
 * @package froq\encrypting\twoway
 * @class   froq\encrypting\twoway\Cryptee
 * @author  Kerem Güneş
 * @since   3.0
 */
class Cryptee extends Twoway
{
    /**
     * Constructor.
     *
     * @param  string     $key
     * @param  array|null $options
     * @throws froq\encrypting\twoway\TwowayException
     */
    public function __construct(string $key, array $options = null)
    {
        parent::checkKeyLength(strlen($key));

        $options = ['key' => $key] + (array) $options;

        parent::__construct($options);
    }

    /**
     * @inheritDoc froq\encrypting\twoway\Twoway
     */
    public function encrypt(string $input, bool $raw = false): string|null
    {
        $ret = $this->process($input);

        return $raw ? $ret : $this->encode($ret);
    }

    /**
     * @inheritDoc froq\encrypting\twoway\Twoway
     */
    public function decrypt(string $input, bool $raw = false): string|null
    {
        $input = $raw ? $input : $this->decode($input);

        // Invalid.
        if ($input === null) {
            return null;
        }

        return $this->process($input);
    }

    /**
     * Process encrypt/decrypt operation.
     */
    private function process(string $input): string
    {
        $top = 256;
        $key = $cnt = [];

        for ($i = 0, $il = strlen($this->options['key']); $i < $top; $i++) {
            $key[$i] = ord(substr($this->options['key'], ($i % $il) + 1, 1));
            $cnt[$i] = $i;
        }

        for ($i = 0, $a = 0; $i < $top; $i++) {
            $a = ($a + $cnt[$i] + $key[$i]) % $top;
            $t = $cnt[$i];

            $cnt[$i] = $cnt[$a] ?? 0;
            $cnt[$a] = $t;
        }

        $ret = b'';

        for ($i = 0, $a = -1, $b = -1, $il = strlen($input); $i < $il; $i++) {
            $a = ($a + 1) % $top;
            $b = ($b + $cnt[$a]) % $top;
            $t = $cnt[$a];

            $cnt[$a] = $cnt[$b] ?? 0;
            $cnt[$b] = $t;

            $ret .= chr(ord(substr($input, $i, 1)) ^ $cnt[($cnt[$a] + $cnt[$b]) % $top]);
        }

        return $ret;
    }
}
