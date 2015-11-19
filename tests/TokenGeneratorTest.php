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

class TokenGeneratorTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var \Firebase\Token\TokenGenerator
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

    public function testDefaultOptions()
    {
        $token = $this->generator->setData(['uid' => 'uid'])->create();
        $data  = $this->decodeToken($token);

        $this->assertFalse($data->admin);
        $this->assertFalse($data->debug);
        $this->assertObjectNotHasAttribute('exp', $data);
        $this->assertObjectNotHasAttribute('nbf', $data);
    }

    public function testSetOptions()
    {
        $notBefore = time() - 10;
        $expires   = time() + 10;

        $token = $this->generator
            ->setData(['uid' => 'uid'])
            ->setOptions([
                'admin'     => true,
                'debug'     => true,
                'expires'   => $expires,
                'notBefore' => $notBefore,
            ])
            ->create();
        $check = $this->decodeToken($token);

        $this->assertTrue($check->admin);
        $this->assertTrue($check->debug);
        $this->assertEquals($expires, $check->exp);
        $this->assertEquals($notBefore, $check->nbf);
    }

    public function testTriggerExceptionOnUnsupportedOption()
    {
        $this->setExpectedExceptionRegExp('\Firebase\Token\TokenException', '/^Unsupported option "foo"/');
        $this->generator->setOption('foo', 'bar');
    }

    /**
     * @param string $name
     * @param string $expectedType
     * @param mixed  $invalidValue
     *
     * @dataProvider invalidOptionsProvider
     */
    public function testTriggerExceptionOnInvalidOption($name, $expectedType, $invalidValue)
    {
        $this->setExpectedException(
            '\Firebase\Token\TokenException',
            sprintf('Invalid option "%s". Expected %s, but %s given', $name, $expectedType, gettype($invalidValue))
        );

        $this->generator->setOption($name, $invalidValue);
    }

    public function invalidOptionsProvider()
    {
        return [
            ['admin', 'bool', 'foo'],
            ['debug', 'bool', 'foo'],
            ['expires', 'int or DateTime', 'foo'],
            ['notBefore', 'int or DateTime', 'foo'],
        ];
    }

    /**
     * @expectedException \Firebase\Token\TokenException
     * @expectedExceptionMessage The Firebase secret must be a string, integer given.
     */
    public function testTriggerExceptionOnInvalidSecret()
    {
        new TokenGenerator(1);
    }

    /**
     * @expectedException \Firebase\Token\TokenException
     * @expectedExceptionMessage No uid provided in data and admin option not set.
     */
    public function testTriggerExceptionOnMissingUid()
    {
        $this->generator->create();
    }

    /**
     * @expectedException \Firebase\Token\TokenException
     * @expectedExceptionMessage The uid must be a string, integer given.
     */
    public function testTriggerExceptionOnNonStringUid()
    {
        $this->generator->setData(['uid' => 1])->create();
    }

    public function testTriggerExceptionIfUidIsTooLong()
    {
        $this->setExpectedException(
            '\Firebase\Token\TokenException',
            sprintf(
                'The provided uid is longer than %d bytes (%d)',
                TokenGenerator::MAX_UID_SIZE, TokenGenerator::MAX_UID_SIZE + 1
            )
        );

        $this->generator->setData(['uid' => str_repeat('x', TokenGenerator::MAX_UID_SIZE + 1)])->create();
    }

    /**
     * @expectedException \Firebase\Token\TokenException
     * @expectedExceptionMessage The provided uid is empty.
     */
    public function testTriggerExceptionIfUidIsEmpty()
    {
        $this->generator->setData(['uid' => ''])->create();
    }

    public function testTriggerExceptionIfGeneratedTokenIsTooLong()
    {
        $expectedMessagePattern = sprintf(
            '/^The generated token is larger than %d bytes \(\d+\)$/', TokenGenerator::MAX_TOKEN_SIZE
        );

        $this->setExpectedExceptionRegExp('\Exception', $expectedMessagePattern);

        $this->generator
            ->setData(['uid' => 'uid', 'foo' => str_repeat('x', TokenGenerator::MAX_TOKEN_SIZE + 1)])
            ->create();
    }

    public function testAllowEmptyUidIfAdminOptionIsSet()
    {
        $token = $this->generator->setOption('admin', true)->create();
        $data  = $this->decodeToken($token);

        $this->assertTrue($data->admin);
    }

    /**
     * @expectedException \Firebase\Token\TokenException
     */
    public function testTriggerExceptionOnJwtException()
    {
        $this->generator
            ->setData(['uid' => "\xB1\x31"]) // Invalid UTF-8 character
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
