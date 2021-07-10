<?php
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-encrypting
 */
declare(strict_types=1);

namespace froq\encrypting\twoway;

use froq\encrypting\{Suid, Base62, Base64};
use froq\encrypting\twoway\TwowayException;

/**
 * Twoway.
 *
 * Represents a abstract class entity that used in `twoway` package only, and also provides encrypt/decrypt
 * methods as shortcut for encode/decode methods of extender classes.
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
     * Encrypt given data by given options.
     *
     * @param  string $data
     * @param  array  $options
     * @return string|null
     * @since  4.5
     */
    public static final function encrypt(string $data, array $options): string|null
    {
        // Key is required, nonce for Sodium, method for OpenSsl.
        $that = new static($options['key'] ?? '', $options['nonce'] ?? $options['method'] ?? null);

        if (isset($options['type'])) {
            $data = $that->encode($data, true);

            $data = match ($options['type']) {
                'base62'    => $data ? Base62::encode($data, 16, true) : null,
                'base64'    => $data ? Base64::encode($data) : null,
                'base64url' => $data ? Base64::encodeUrlSafe($data) : null,
                default     => throw new TwowayException(
                    'Invalid type `%s`, valids are: base62, base64, base64url',
                    $options['type']
                )
            };

            return $data;
        }

        return $that->encode($data);
    }

    /**
     * Decrypt given data by given options.
     *
     * @param  string $data
     * @param  array  $options
     * @return string|null
     * @since  4.5
     */
    public static final function decrypt(string $data, array $options): string|null
    {
        // Key is required, nonce for Sodium, method for OpenSsl.
        $that = new static($options['key'] ?? '', $options['nonce'] ?? $options['method'] ?? null);

        if (isset($options['type'])) {
            $data = match ($options['type']) {
                'base62'    => Base62::decode($data, 16, true),
                'base64'    => Base64::decode($data),
                'base64url' => Base64::decodeUrlSafe($data),
                default     => throw new TwowayException(
                    'Invalid type `%s`, valids are: base62, base64, base64url',
                    $options['type']
                )
            };

            return $that->decode($data, true);
        }

        return $that->decode($data);
    }

    /**
     * Encode given data.
     *
     * @param  string $data
     * @param  bool   $raw
     * @return string|null
     */
    abstract public function encode(string $data, bool $raw = false): string|null;

    /**
     * Decode given data.
     *
     * @param  string $data
     * @param  bool   $raw
     * @return string|null
     */
    abstract public function decode(string $data, bool $raw = false): string|null;
}
