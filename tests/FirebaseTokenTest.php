<?php

include_once "FirebaseToken.php";

class FirebaseTokenTest extends PHPUnit_Framework_TestCase {
  function testCreate() {
    $key = "0014ae3b1ded44de9d9f6fc60dfd1c64";
    $tokenGen = new FirebaseTokenGenerator($key);
    $token = $tokenGen->createToken(array("foo" => "bar", "baz" => "boo"));
    
    $data = JWT::decode($token, $key);
    $this->assertEquals("bar", $data->d->foo);
    $this->assertEquals("boo", $data->d->baz);
    $this->assertInternalType("integer", $data->iat);
  }

  function testAdminDebug() {
    $key = "foobar";
    $tokenGen = new FirebaseTokenGenerator($key);
    $token = $tokenGen->createToken(null, true, true);
    
    $data = JWT::decode($token, $key);
    $this->assertTrue($data->admin);
    $this->assertTrue($data->debug);
  }

  function testMalformedKeyThrowsException() {
    $this->setExpectedException("UnexpectedValueException");
    $tokenGen = new FirebaseTokenGenerator(1234567890);
  }
}

?>
