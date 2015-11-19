<?php

/*
 * This file is part of the Firebase Token Generator.
 *
 * This source file is subject to the license that is bundled
 * with this source code in the file LICENSE.
 */

namespace Firebase\Token;

use Firebase\JWT\JWT;

/**
 * Creates JWT token to to authenticate requests to a Firebase application.
 */
class TokenGenerator
{
    // Sizes in bytes
    const MAX_UID_SIZE   = 256;
    const MAX_TOKEN_SIZE = 1024;

    /**
     * The token data.
     *
     * @var mixed[]
     */
    private $data;

    /**
     * The token options.
     *
     * @var mixed[]
     */
    private $options;

    /**
     * The Firebase secret.
     *
     * @var string
     */
    private $secret;

    /**
     * Initializes the generator.
     *
     * @param string $secret The Firebase secret.
     *
     * @throws TokenException If an invalid secret has been given.
     */
    public function __construct($secret)
    {
        if (!is_string($secret)) {
            throw new TokenException(
                sprintf('The Firebase secret must be a string, %s given.', gettype($secret))
            );
        }

        $this->secret = $secret;
        $this->data   = [];

        // Default options
        $this->options = [
            'admin'     => false,
            'debug'     => false,
            'expires'   => null,
            'notBefore' => null,
        ];
    }

    /**
     * Sets the token data.
     *
     * @param array $data An array of data you wish to associate with the token.
     *                    It will be available as the variable "auth" in the Firebase rules engine.
     *
     * @return static
     */
    public function setData(array $data)
    {
        $this->data = $data;

        return $this;
    }

    /**
     * Sets multiple options.
     *
     * @see setOption()
     *
     * @param array $options The options.
     *
     * @throws TokenException If an invalid option has been given.
     *
     * @return static
     */
    public function setOptions(array $options)
    {
        foreach ($options as $name => $value) {
            $this->setOption($name, $value);
        }

        return $this;
    }

    /**
     * Sets an option.
     *
     * @param string $name  The option name.
     * @param mixed  $value The option value.
     *
     * @throws TokenException If an invalid option has been given.
     *
     * @return static
     */
    public function setOption($name, $value)
    {
        if (!array_key_exists($name, $this->options)) {
            throw new TokenException(
                sprintf(
                    'Unsupported option "%s". Valid options are: %s', $name, implode(', ', array_keys($this->options))
                )
            );
        }

        switch ($name) {
            case 'admin':
            case 'debug':
                if (!is_bool($value)) {
                    throw new TokenException(
                        sprintf('Invalid option "%s". Expected %s, but %s given', $name, 'bool', gettype($value))
                    );
                }
                break;
            case 'expires':
            case 'notBefore':
                if (!is_int($value) && !($value instanceof \DateTime)) {
                    throw new TokenException(
                        sprintf(
                            'Invalid option "%s". Expected %s, but %s given',
                            $name, 'int or DateTime', gettype($value)
                        )
                    );
                }

                if (is_int($value)) {
                    $value = \DateTime::createFromFormat('U', $value);
                }
                break;
        }

        $this->options[$name] = $value;

        return $this;
    }

    /**
     * Creates the token.
     *
     * @throws TokenException If the token couldn't be generated or is invalid.
     *
     * @return string The JWT token.
     */
    public function create()
    {
        $this->validate();

        $claims        = $this->processOptions();
        $claims['d']   = $this->data;
        $claims['v']   = 0;
        $claims['iat'] = time();

        try {
            $token = JWT::encode($claims, $this->secret, 'HS256');
        } catch (\Exception $e) {
            throw new TokenException($e->getMessage(), null, $e);
        }

        if (($tokenSize = mb_strlen($token, '8bit')) > static::MAX_TOKEN_SIZE) {
            throw new TokenException(
                sprintf('The generated token is larger than %d bytes (%d)', static::MAX_TOKEN_SIZE, $tokenSize)
            );
        }

        return $token;
    }

    /**
     * Parses provided options into a claims array.
     *
     * @return array The claims.
     */
    private function processOptions()
    {
        $claims = [];

        foreach ($this->options as $name => $value) {
            switch ($name) {
                case 'expires':
                    if ($value instanceof \DateTime) {
                        $claims['exp'] = $value->getTimestamp();
                    }
                    break;
                case 'notBefore':
                    if ($value instanceof \DateTime) {
                        $claims['nbf'] = $value->getTimestamp();
                    }
                    break;
                default:
                    $claims[$name] = $value;
                    break;
            }
        }

        return $claims;
    }

    /**
     * Validates the combination of data and options.
     *
     * @throws TokenException If the combination of data and options is invalid.
     */
    private function validate()
    {
        if (false === $this->options['admin'] && !array_key_exists('uid', $this->data)) {
            throw new TokenException('No uid provided in data and admin option not set.');
        }

        if (array_key_exists('uid', $this->data)) {
            $this->validateUid($this->data['uid']);
        }
    }

    /**
     * Validates an uid.
     *
     * @param string $uid The uid.
     *
     * @throws TokenException If the uid is invalid.
     */
    private function validateUid($uid)
    {
        if (!is_string($uid)) {
            throw new TokenException(sprintf('The uid must be a string, %s given.', gettype($uid)));
        }

        $uidSize = mb_strlen($uid, '8bit');

        if ($uidSize > static::MAX_UID_SIZE) {
            throw new TokenException(
                sprintf('The provided uid is longer than %d bytes (%d).', static::MAX_UID_SIZE, $uidSize)
            );
        }

        if (0 === $uidSize) {
            throw new TokenException('The provided uid is empty.');
        }
    }
}
