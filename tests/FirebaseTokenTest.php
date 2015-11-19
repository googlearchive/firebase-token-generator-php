<?php

/*
 * This file is part of the Firebase Token Generator.
 *
 * This source file is subject to the license that is bundled
 * with this source code in the file LICENSE.
 */

namespace Firebase\Token\Tests;

use Firebase\JWT\JWT;
use Firebase\Token\TokenGenerator;

/**
 * Tests for the Legacy \Services_FirebaseTokenGenerator class.
 */
class FirebaseTokenTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var TokenGenerator
     */
    protected $generator;

    /**
     * @var string
     */
    protected $secret;

    protected function setUp()
    {
        $this->secret    = 'secret';
        $this->generator = new TokenGenerator($this->secret);
    }

    public function testCreate()
    {
        $token = $this->generator
            ->setData(['foo' => 'bar', 'baz' => 'boo', 'uid' => 'blah'])
            ->create();

        $data = $this->decodeToken($token);

        $this->assertEquals('bar', $data->d->foo);
        $this->assertEquals('boo', $data->d->baz);
        $this->assertInternalType('integer', $data->iat);
    }

    public function testAdmin()
    {
        $token = $this->generator
            ->setOption('admin', true)
            ->create();

        $data = $this->decodeToken($token);

        $this->assertTrue($data->admin);
    }

    public function testDebug()
    {
        $token = $this->generator
            ->setData(['uid' => 'uid'])
            ->setOption('debug', true)
            ->create();

        $data = $this->decodeToken($token);

        $this->assertTrue($data->debug);
    }

    /**
     * @expectedException \Firebase\Token\TokenException
     * @expectedExceptionMessage The Firebase secret must be a string, integer given.
     */
    public function testMalformedKeyThrowsException()
    {
        new TokenGenerator(1234567890);
    }

    public function testExpires()
    {
        $expires = time() + 1000;

        $token = $this->generator
            ->setData(['uid' => 'uid'])
            ->setOption('expires', $expires)
            ->create();

        $data = $this->decodeToken($token);

        $this->assertEquals($expires, $data->exp);
    }

    public function testNotBeforeObject()
    {
        $notBefore = new \DateTime('now', new \DateTimeZone('America/Los_Angeles'));

        $token = $this->generator
            ->setData(['uid' => 'uid'])
            ->setOption('notBefore', $notBefore)
            ->create();

        $data = $this->decodeToken($token);

        $this->assertEquals($notBefore->getTimestamp(), $data->nbf);
    }

    /**
     * @expectedException \Firebase\Token\TokenException
     * @expectedExceptionMessage No uid provided in data and admin option not set.
     */
    public function testNoUID()
    {
        $this->generator
            ->setData(['blah' => 5])
            ->create();
    }

    /**
     * @expectedException \Firebase\Token\TokenException
     * @expectedExceptionMessage The uid must be a string, integer given.
     */
    public function testInvalidUID()
    {
        $this->generator
            ->setData(['uid' => 5])
            ->create();
    }

    public function testUIDTooLong()
    {
        $this->setExpectedException(
            '\Firebase\Token\TokenException',
            sprintf(
                'The provided uid is longer than %d bytes (%d)',
                TokenGenerator::MAX_UID_SIZE, TokenGenerator::MAX_UID_SIZE + 1
            )
        );

        $this->generator
            ->setData(['uid' => str_repeat('x', TokenGenerator::MAX_UID_SIZE + 1)])
            ->create();
    }

    /**
     * @expectedException \Firebase\Token\TokenException
     * @expectedExceptionMessage The provided uid is empty
     */
    public function testUIDMinLength()
    {
        $this->generator
            ->setData(['uid' => ''])
            ->create();
    }

    public function testTokenTooLong()
    {
        $expectedMessagePattern = sprintf(
            '/^The generated token is larger than %d bytes \(\d+\)$/', TokenGenerator::MAX_TOKEN_SIZE
        );

        $this->setExpectedExceptionRegExp('\Exception', $expectedMessagePattern);

        $this->generator
            ->setData([
                'uid'     => 'uid',
                'longVar' => str_repeat('x', TokenGenerator::MAX_TOKEN_SIZE + 1),
            ])
            ->create();
    }

    public function testNoUIDWithAdmin()
    {
        $token = $this->generator
            ->setOption('admin', true)
            ->create();

        $data = $this->decodeToken($token);

        $this->assertTrue($data->admin);
    }

    /**
     * @expectedException \Firebase\Token\TokenException
     * @expectedExceptionMessage The uid must be a string, integer given.
     */
    public function testInvalidUIDWithAdmin1()
    {
        $this->generator
            ->setData(['uid' => 1])
            ->setOption('admin', true)
            ->create();
    }

    /**
     * @expectedException \Firebase\Token\TokenException
     * @expectedExceptionMessage The uid must be a string, NULL given.
     */
    public function testInvalidUIDWithAdmin2()
    {
        $this->generator
            ->setData(['uid' => null])
            ->setOption('admin', true)
            ->create();
    }

    /**
     * @expectedException \Firebase\Token\TokenException
     * @expectedExceptionMessage No uid provided in data and admin option not set.
     */
    public function testEmptyDataAndNoOptionsThrowsException()
    {
        $this->generator->create();
    }

    /**
     * @expectedException \Firebase\Token\TokenException
     */
    public function testMalformedDataThrowsException()
    {
        $this->generator
            ->setData(['uid' => 'uid', 'var' => "\xB1\x31"])
            ->create();
    }

    /**
     * Decodes a token.
     *
     * @param string $token
     *
     * @return object
     */
    protected function decodeToken($token)
    {
        return JWT::decode($token, $this->secret, ['HS256']);
    }
}
