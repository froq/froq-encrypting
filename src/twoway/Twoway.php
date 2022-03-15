<?php
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-encrypting
 */
declare(strict_types=1);

namespace froq\encrypting\twoway;

use froq\encrypting\{Suid, Base62, Base64};

/**
 * Twoway.
 *
 * An abstract class, used in `twoway` package only, also provides doEncrypt/doDecrypt
 * methods as shortcut for encrypt/decrypt methods of extender classes.
 *
 * @package froq\encrypting\twoway
 * @object  froq\encrypting\twoway\Twoway
 * @author  Kerem Güneş
 * @since   3.0
 */
abstract class Twoway
{
    /** @var string */
    protected string $key;

    /**
     * Constructor.
     * @param string $key
     */
    public function __construct(string $key)
    {
        $this->key = $key;
    }

    /**
     * Get key property.
     *
     * @return string
     */
    public final function key(): string
    {
        return $this->key;
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
     * Encrypt given input by given options.
     *
     * @param  string $input
     * @param  array  $options
     * @return string|null
     * @since  4.5
     */
    public static final function doEncrypt(string $input, array $options): string|null
    {
        // Key is required, nonce for Sodium, method for OpenSsl.
        $that = new static($options['key'] ?? '', $options['nonce'] ?? $options['method'] ?? null);

        if (isset($options['type'])) {
            $input = $that->encrypt($input, true);

            $input = match ($options['type']) {
                'base62'    => $input ? Base62::encode($input, true)  : null,
                'base64'    => $input ? Base64::encode($input)        : null,
                'base64url' => $input ? Base64::encodeUrlSafe($input) : null,

                default => throw new TwowayException(
                    'Invalid type `%s` [valids: base62, base64, base64url]',
                    $options['type']
                )
            };

            return $input;
        }

        return $that->encrypt($input);
    }

    /**
     * Decrypt given input by given options.
     *
     * @param  string $input
     * @param  array  $options
     * @return string|null
     * @since  4.5
     */
    public static final function doDecrypt(string $input, array $options): string|null
    {
        // Key is required, nonce for Sodium, method for OpenSsl.
        $that = new static($options['key'] ?? '', $options['nonce'] ?? $options['method'] ?? null);

        if (isset($options['type'])) {
            $input = match ($options['type']) {
                'base62'    => Base62::decode($input, true),
                'base64'    => Base64::decode($input),
                'base64url' => Base64::decodeUrlSafe($input),

                default => throw new TwowayException(
                    'Invalid type `%s` [valids: base62, base64, base64url]',
                    $options['type']
                )
            };

            return $that->decrypt($input, true);
        }

        return $that->decrypt($input);
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
