<?php declare(strict_types=1);
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-encrypting
 */
namespace froq\encrypting;

/**
 * A class, provides CSRF operations such as generate/validate in OOP-way.
 *
 * @package froq\encrypting
 * @object  froq\encrypting\Csrf
 * @since   7.2
 */
class Csrf
{
    /** Token length. */
    public const TOKEN_LENGTH = 40;

    /** Token. */
    private string $token;

    /**
     * Constructor.
     *
     * @param string|null $token
     */
    public function __construct(string $token = null)
    {
        $token && $this->setToken($token);
    }

    /**
     * Set token.
     *
     * @param  string $token
     * @return self
     */
    public function setToken(string $token): self
    {
        $this->token = $token;

        return $this;
    }

    /**
     * Get token.
     *
     * @return string|null
     */
    public function getToken(): string|null
    {
        return $this->token ?? null;
    }

    /**
     * @alias validateToken()
     */
    public function validate($tokenUnknown)
    {
        return $this->validateToken($tokenUnknown);
    }

    /**
     * Validate token.
     *
     * @param  string|null $tokenUnknown
     * @return bool
     * @throws froq\encrypting\CsrfException
     */
    public function validateToken(string|null $tokenUnknown): bool
    {
        $tokenKnown = $this->getToken() ?? throw CsrfException::forNoTokenGivenYet();

        return self::validateTokens($tokenKnown, $tokenUnknown);
    }

    /**
     * Validate tokens.
     *
     * @param  string|null $tokenKnown
     * @param  string|null $tokenUnknown
     * @return bool
     */
    public static function validateTokens(string|null $tokenKnown, string|null $tokenUnknown): bool
    {
        return $tokenKnown && $tokenUnknown && hash_equals($tokenKnown, $tokenUnknown);
    }

    /**
     * Generate token.
     *
     * @return string
     */
    public static function generateToken(): string
    {
        return Token::generate(static::TOKEN_LENGTH);
    }
}
