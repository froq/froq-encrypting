<?php declare(strict_types=1);
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-encrypting
 */
namespace froq\encrypting\twoway;

use froq\encrypting\{Suid, Base, Base62, Base64};
use froq\common\trait\OptionTrait;

/**
 * Base class of `twoway` classes.
 *
 * @package froq\encrypting\twoway
 * @class   froq\encrypting\twoway\Twoway
 * @author  Kerem Güneş
 * @since   3.0
 */
abstract class Twoway
{
    use OptionTrait;

    /**
     * Constructor.
     *
     * @param array|null $options
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
    public static function generateKey(int $length = 40): string
    {
        return Suid::generate($length);
    }

    /**
     * Check key length.
     *
     * @param  int $length
     * @param  int $lengthMinimum
     * @return void
     * @throws froq\encrypting\twoway\{CrypteeException|OpenSslException|SodiumException}
     * @since  6.0
     */
    public static function checkKeyLength(int $length, int $lengthMinimum = 16): void
    {
        if ($length < $lengthMinimum) {
            throw TwowayException::forMinimumKeyLength(
                static::class, $length, $lengthMinimum
            );
        }
    }

    /**
     * Encode given input.
     *
     * @param  string $input
     * @return string|null
     * @throws froq\encrypting\twoway\{CrypteeException|OpenSslException|SodiumException}
     * @since  6.0
     */
    protected function encode(string $input): string|null
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
                        throw TwowayException::forInvalidConvertOption(
                            static::class, $this->options['convert']
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
     * @throws froq\encrypting\twoway\{CrypteeException|OpenSslException|SodiumException}
     * @since  6.0
     */
    protected function decode(string $input): string|null
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
                        throw TwowayException::forInvalidConvertOption(
                            static::class, $this->options['convert']
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
