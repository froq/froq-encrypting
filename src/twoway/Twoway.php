<?php
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 <https://opensource.org/licenses/apache-2.0>
 */
declare(strict_types=1);

namespace froq\encrypting\twoway;

use froq\encrypting\{Salt, Base, Base64};
use froq\encrypting\twoway\TwowayException;

/**
 * Twoway.
 *
 * @package froq\encrypting\twoway
 * @object  froq\encrypting\twoway\Twoway
 * @author  Kerem Güneş <k-gun@mail.com>
 * @since   3.0
 */
abstract class Twoway
{
    /**
     * Key.
     * @var string
     */
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
     * Get key.
     * @return string
     */
    public final function getKey(): string
    {
        return $this->key;
    }

    /**
     * Generate key.
     * @param  int $length
     * @return string
     */
    public static final function generateKey(int $length = 40): string
    {
        return Salt::generate($length);
    }

    /**
     * Encrypt.
     * @param  string $data
     * @param  array  $options
     * @return ?string
     * @since  4.5
     */
    public static final function encrypt(string $data, array $options): ?string
    {
        // Key is required, nonce for Sodium, method for OpenSsl.
        $that = new static($options['key'] ?? '', $options['nonce'] ?? $options['method'] ?? null);

        if (isset($options['type'])) {
            $data = $that->encode($data, true);

            $data = match ($options['type']) {
                'base62'    => $data ? Base::encode($data) : null,
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
     * Decrypt.
     * @param  string $data
     * @param  array  $options
     * @return ?string
     * @since  4.5
     */
    public static final function decrypt(string $data, array $options): ?string
    {
        // Key is required, nonce for Sodium, method for OpenSsl.
        $that = new static($options['key'] ?? '', $options['nonce'] ?? $options['method'] ?? null);

        if (isset($options['type'])) {
            $data = match ($options['type']) {
                'base62'    => Base::decode($data),
                'base64'    => Base64::decode($data),
                'base64url' => Base64::decodeUrlSafe($data),
                default     => throw new TwowayException(
                    'Invalid type `%s`, valids are: base62, base64, base64url',
                    $options['type'
                ])
            };

            return $that->decode($data, true);
        }

        return $that->decode($data);
    }

    /**
     * Encode.
     * @param  string $data
     * @param  bool   $raw
     * @return ?string
     */
    public abstract function encode(string $data, bool $raw = false): ?string;

    /**
     * Decode.
     * @param  string $data
     * @param  bool   $raw
     * @return ?string
     */
    public abstract function decode(string $data, bool $raw = false): ?string;
}
