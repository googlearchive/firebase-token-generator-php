<?php

/*
 * This file is part of the Firebase Token Generator.
 *
 * This source file is subject to the license that is bundled
 * with this source code in the file LICENSE.
 */

namespace Firebase\Token\Tests;

/**
 * Tests for the Legacy \Services_FirebaseTokenGenerator class.
 */
class FirebaseTokenTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var \Services_FirebaseTokenGenerator
     */
    protected $generator;

    /**
     * @var string
     */
    protected $secret;

    protected function setUp()
    {
        $this->secret    = 'secret';
        $this->generator = new \Services_FirebaseTokenGenerator($this->secret);
    }

    public function testCreate()
    {
        $token = $this->generator->createToken(['foo' => 'bar', 'baz' => 'boo', 'uid' => 'blah']);

        $data = $this->decodeToken($token);

        $this->assertEquals('bar', $data->d->foo);
        $this->assertEquals('boo', $data->d->baz);
        $this->assertInternalType('integer', $data->iat);
    }

    public function testAdminDebug()
    {
        $token = $this->generator->createToken(null, ['admin' => true, 'debug' => true]);

        $data = $data = $this->decodeToken($token);

        $this->assertTrue($data->admin);
        $this->assertTrue($data->debug);
    }

    /**
     * @expectedException \Firebase\Token\TokenException
     * @expectedExceptionMessage The Firebase secret must be a string, integer given.
     */
    public function testMalformedKeyThrowsException()
    {
        new \Services_FirebaseTokenGenerator(1234567890);
    }

    public function testExpires()
    {
        $expires = time() + 1000;

        $token = $this->generator->createToken(['uid' => 'blah'], ['expires' => $expires]);

        $data = $data = $this->decodeToken($token);

        $this->assertEquals($expires, $data->exp);
    }

    public function testNotBeforeObject()
    {
        $notBefore = new \DateTime('now', new \DateTimeZone('America/Los_Angeles'));

        $token = $this->generator->createToken(['uid' => 'blah'], ['notBefore' => $notBefore]);

        $data = $data = $this->decodeToken($token);

        $this->assertEquals($notBefore->getTimestamp(), $data->nbf);
    }

    /**
     * @expectedException \Firebase\Token\TokenException
     * @expectedExceptionMessage No uid provided in data and admin option not set.
     */
    public function testNoUID()
    {
        $this->generator->createToken(['blah' => 5]);
    }

    /**
     * @expectedException \Firebase\Token\TokenException
     * @expectedExceptionMessage The uid must be a string, integer given.
     */
    public function testInvalidUID()
    {
        $this->generator->createToken(['uid' => 5, 'blah' => 5]);
    }

    public function testUIDTooLong()
    {
        $this->setExpectedException(
            '\Firebase\Token\TokenException',
            sprintf(
                'The provided uid is longer than %d bytes (%d)',
                \Firebase\Token\TokenGenerator::MAX_UID_SIZE, \Firebase\Token\TokenGenerator::MAX_UID_SIZE + 1
            )
        );

        $this->generator->createToken(['uid' => str_repeat('x', \Firebase\Token\TokenGenerator::MAX_UID_SIZE + 1)]);
    }

    /**
     * @expectedException \Firebase\Token\TokenException
     * @expectedExceptionMessage The provided uid is empty
     */
    public function testUIDMinLength()
    {
        $this->generator->createToken(['uid' => '']);
    }

    public function testTokenTooLong()
    {
        $expectedMessagePattern = sprintf(
            '/^The generated token is larger than %d bytes \(\d+\)$/', \Firebase\Token\TokenGenerator::MAX_TOKEN_SIZE
        );

        $this->setExpectedExceptionRegExp('\Exception', $expectedMessagePattern);

        $this->generator->createToken([
            'uid'     => 'uid',
            'longVar' => str_repeat('x', \Firebase\Token\TokenGenerator::MAX_TOKEN_SIZE + 1),
        ]);
    }

    public function testNoUIDWithAdmin()
    {
        $token = $this->generator->createToken(null, ['admin' => true]);

        $data = $this->decodeToken($token);

        $this->assertTrue($data->admin);
    }

    /**
     * @expectedException \Firebase\Token\TokenException
     * @expectedExceptionMessage The uid must be a string, integer given.
     */
    public function testInvalidUIDWithAdmin1()
    {
        $this->generator->createToken(['uid' => 1], ['admin' => true]);
    }

    /**
     * @expectedException \Firebase\Token\TokenException
     * @expectedExceptionMessage The uid must be a string, NULL given.
     */
    public function testInvalidUIDWithAdmin2()
    {
        $this->generator->createToken(['uid' => null], ['admin' => true]);
    }

    /**
     * @expectedException \Firebase\Token\TokenException
     * @expectedExceptionMessage $data must be an array, an object or null.
     */
    public function testInvalidUIDWithAdmin3()
    {
        $this->generator->createToken('foo', ['admin' => true]);
    }

    /**
     * @expectedException \Firebase\Token\TokenException
     * @expectedExceptionMessage No uid provided in data and admin option not set.
     */
    public function testEmptyDataAndNoOptionsThrowsException()
    {
        $this->generator->createToken(null);
    }

    /**
     * @expectedException \Firebase\Token\TokenException
     */
    public function testMalformedDataThrowsException()
    {
        $this->generator->createToken(['uid' => 'uid', 'var' => "\xB1\x31"]);
    }

    public function testObjectIsTreatedAsArray()
    {
        $token = $this->generator->createToken((object) ['uid' => 'uid']);

        $data = $this->decodeToken($token);

        $this->assertEquals('uid', $data->d->uid);
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
        return \JWT::decode($token, $this->secret, ['HS256']);
    }
}
