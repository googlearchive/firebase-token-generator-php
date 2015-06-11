<?php

/*
 * This file is part of the Firebase Token Generator.
 *
 * This source file is subject to the license that is bundled
 * with this source code in the file LICENSE.
 */

use Firebase\Token\TokenGenerator;

class Services_FirebaseTokenGenerator
{
    /**
     * @var TokenGenerator
     */
    private $generator;

    /**
     * @deprecated Use \Firebase\Token\TokenGenerator instead.
     *
     * @param string $secret
     */
    public function __construct($secret)
    {
        $this->generator = new TokenGenerator($secret);
    }

    /**
     * @deprecated Use \Firebase\Token\TokenGenerator instead.
     *
     * @param array|object|null $data
     * @param array|null        $options
     *
     * @throws \Firebase\Token\TokenException If the given data or options contain invalid items.
     *
     * @return string
     */
    public function createToken($data, $options = null)
    {
        $generator = $this->generator;

        if (is_scalar($data)) {
            throw new \Firebase\Token\TokenException('$data must be an array, an object or null.');
        }

        if (is_object($data)) {
            $data = json_decode(json_encode($data), true);
        }

        if (is_array($data)) {
            $generator->setData($data);
        }

        if (is_array($options)) {
            $generator->setOptions($options);
        }

        return $generator->create();
    }
}
