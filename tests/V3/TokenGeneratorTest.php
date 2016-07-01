<?php


namespace Firebase\Tests\Token\V3;

use Firebase\Token\V3\ServiceAccount;
use Firebase\Token\V3\TokenGenerator;

/**
 * We don't test the generated tokens, because the token generation is done by the JWT library.
 */
class TokenGeneratorTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var TokenGenerator
     */
    private $generator;

    protected function setUp()
    {
        $this->generator = new TokenGenerator(ServiceAccount::fromKeyFile(__DIR__.'/_fixtures/valid_key_file.json'));
    }

    public function testCreateCustomToken()
    {
        $this->assertInternalType('string', $this->generator->createCustomToken('uid', ['foo' => 'bar'], 1800));
    }

    public function testPutGeneratorIntoDebugMode()
    {
        $generator = $this->generator->withEnabledDebug();

        $this->assertNotSame($this->generator, $generator);
        $this->assertTrue($generator->isDebugEnabled());

        $this->assertInternalType('string', $generator->createCustomToken('uid'));
    }

    public function testPutGeneratorBackIntoDefaultMode()
    {
        $withEnabledDebug = $this->generator->withEnabledDebug();
        $withDisabledDebug = $withEnabledDebug->withDisabledDebug();

        $this->assertNotSame($this->generator, $withDisabledDebug);
        $this->assertNotSame($withEnabledDebug, $withDisabledDebug);
        $this->assertFalse($withDisabledDebug->isDebugEnabled());
    }

    /**
     * @param $uid
     *
     * @expectedException \InvalidArgumentException
     *
     * @dataProvider invalidUidProvider
     */
    public function testInvalidUidTriggersException($uid)
    {
        $this->generator->createCustomToken($uid);
    }

    /**
     * @param $expirationTime
     *
     * @expectedException \InvalidArgumentException
     *
     * @dataProvider  invalidExpirationTimeProvider
     */
    public function testInvalidExpirationTimeTriggersException($expirationTime)
    {
        $this->generator->createCustomToken('uid', [], $expirationTime);
    }

    /**
     * @expectedException \InvalidArgumentException
     */
    public function testReservedClaimTriggersException()
    {
        $this->generator->createCustomToken('uid', ['sub' => 'sub']);
    }

    public function invalidUidProvider()
    {
        return [
            ['empty' => ''],
            ['invalid_type' => 1],
            ['too_long' => str_repeat('a', 37)],
        ];
    }

    public function invalidExpirationTimeProvider()
    {
        return [
            ['invalid_type' => 'string'],
            ['too_big' => 3601],
        ];
    }
}
