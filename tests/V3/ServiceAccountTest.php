<?php

namespace Firebase\Token\Tests\V3;

use Firebase\Token\V3\ServiceAccount;

class ServiceAccountTest extends \PHPUnit_Framework_TestCase
{
    private $projectId;
    private $serviceAccountEmail;
    private $privateKey;

    private $keyFile;

    protected function setUp()
    {
        $this->serviceAccountEmail = 'project@domain.tld';
        $this->privateKey = 'private_key';

        $this->keyFile = __DIR__.'/_fixtures/valid_key_file.json';
    }

    public function testCreate()
    {
        $account = new ServiceAccount($this->serviceAccountEmail, $this->privateKey);

        $this->assertEquals($this->serviceAccountEmail, $account->getClientEmail());
        $this->assertEquals($this->privateKey, $account->getPrivateKey());
    }

    public function testCreateFromKeyFile()
    {
        $this->assertInstanceOf('\Firebase\Token\V3\ServiceAccount', ServiceAccount::fromKeyFile($this->keyFile));
    }

    /**
     * @param string $invalidKeyFile
     *
     * @expectedException \InvalidArgumentException
     *
     * @dataProvider invalidKeyFilesProvider
     */
    public function testInvalidKeyFileTriggersException($invalidKeyFile)
    {
        ServiceAccount::fromKeyFile($invalidKeyFile);
    }

    /**
     * @expectedException \InvalidArgumentException
     */
    public function testInvalidEmailThrowsException()
    {
        new ServiceAccount($this->projectId, 'invalid_email', $this->privateKey);
    }

    public function invalidKeyFilesProvider()
    {
        return [
            ['non_existing' => __DIR__.'/_fixtures/non_existing.json'],
            ['invalid' => __DIR__.'/_fixtures/invalid_key_file'],
            ['missing_client_email' => __DIR__.'/_fixtures/missing_client_email.json'],
            ['missing_private_key' => __DIR__.'/_fixtures/missing_private_key.json'],
        ];
    }
}
