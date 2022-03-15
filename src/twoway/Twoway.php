<?php
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-encrypting
 */
declare(strict_types=1);

namespace froq\encrypting\twoway;

use froq\encrypting\{Suid, Base, Base62, Base64};
use froq\common\trait\OptionTrait;

/**
 * Twoway.
 *
 * An abstract class, used in `twoway` package only.
 *
 * @package froq\encrypting\twoway
 * @object  froq\encrypting\twoway\Twoway
 * @author  Kerem Güneş
 * @since   3.0
 */
abstract class Twoway
{
    use OptionTrait;

    /**
     * Constructor.
     *
     * @param  array|null $options
     * @throws froq\encrypting\twoway\TwowayException
     */
    public function __construct(array $options = null)
    {
        $this->setOptions($options);
    }

    /**
     * Generate a key.
     *
     * @param  int $length
     * @return string
     */
    public static final function generateKey(int $length = 40): string
    {
        return Suid::generate($length);
    }

    /**
     * Check key length.
     *
     * @param  int $keyLength
     * @param  int $minLength
     * @return void
     * @throws froq\encrypting\twoway\TwowayException
     */
    public static final function checkKeyLength(int $keyLength, int $minLength = 16): void
    {
        // Check key length.
        if ($keyLength < $minLength) {
            throw new TwowayException(
                'Invalid key length `%s`, minimum key length is %s '.
                '[tip: use %s::generateKey() method to get a key]',
                [$keyLength, $minLength, static::class]
            );
        }
    }

    /**
     * Encode given input.
     *
     * @param  string $input
     * @return string|null
     * @throws froq\encrypting\twoway\TwowayException
     */
    public final function encode(string $input): string|null
    {
        if (isset($this->options['convert'])) {
            switch ($this->options['convert']) {
                case 'hex'      : return Base::encode($input, Base::HEX_CHARS);
                case 'base62'   : return Base62::encode($input);
                case 'base64'   : return Base64::encode($input);
                case 'base64url': return Base64::encodeUrlSafe($input);

                default:
                    $base = (int) $this->options['convert'];
                    if ($base < 2 || $base > 64) {
                        throw new TwowayException(
                            'Option convert must be between 2-64, %s given',
                            $this->options['convert']
                        );
                    }
                    return Base::encode($input, Base::chars($base));
            }
        }

        // As default.
        return ($ret = base64_encode($input)) !== false ? $ret : null;
    }

    /**
     * Decode given input.
     *
     * @param  string $input
     * @return string|null
     * @throws froq\encrypting\twoway\TwowayException
     */
    public final function decode(string $input): string|null
    {
        if (isset($this->options['convert'])) {
            switch ($this->options['convert']) {
                case 'hex'      : return Base::decode($input, Base::HEX_CHARS);
                case 'base62'   : return Base62::decode($input);
                case 'base64'   : return Base64::decode($input);
                case 'base64url': return Base64::decodeUrlSafe($input);

                default:
                    $base = (int) $this->options['convert'];
                    if ($base < 2 || $base > 64) {
                        throw new TwowayException(
                            'Option convert must be between 2-64, %s given',
                            $this->options['convert']
                        );
                    }
                    return Base::decode($input, Base::chars($base));
            };
        }

        // As default.
        return ($ret = base64_decode($input, true)) !== false ? $ret : null;
    }

    /**
     * Encrypt given input.
     *
     * @param  string $input
     * @param  bool   $raw
     * @return string|null
     */
    abstract public function encrypt(string $input, bool $raw = false): string|null;

    /**
     * Decrypt given input.
     *
     * @param  string $input
     * @param  bool   $raw
     * @return string|null
     */
    abstract public function decrypt(string $input, bool $raw = false): string|null;
}
