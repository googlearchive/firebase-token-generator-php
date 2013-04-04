<?php

include_once "FirebaseToken.php";

class FirebaseTokenTest extends PHPUnit_Framework_TestCase {
  function testCreate() {
    $key = "0014ae3b1ded44de9d9f6fc60dfd1c64";
    $tokenGen = new Services_FirebaseTokenGenerator($key);
    $token = $tokenGen->createToken(array("foo" => "bar", "baz" => "boo"));
    
    $data = JWT::decode($token, $key);
    $this->assertEquals("bar", $data->d->foo);
    $this->assertEquals("boo", $data->d->baz);
    $this->assertInternalType("integer", $data->iat);
  }

  function testAdminDebug() {
    $key = "foobar";
    $tokenGen = new Services_FirebaseTokenGenerator($key);
    $token = $tokenGen->createToken(null, array("admin" => true, "debug" => true));
    
    $data = JWT::decode($token, $key);
    $this->assertTrue($data->admin);
    $this->assertTrue($data->debug);
  }

  function testMalformedKeyThrowsException() {
    $this->setExpectedException("UnexpectedValueException");
    $tokenGen = new Services_FirebaseTokenGenerator(1234567890);
  }

  function testExpires() {
    $key = "barfoo";
    $tokenGen = new Services_FirebaseTokenGenerator($key);
    $expires = time() + 1000;
    $token = $tokenGen->createToken(null, array("expires" => $expires));
    
    $data = JWT::decode($token, $key);
    $this->assertEquals($expires, $data->exp);
  }

  function testNotBeforeObject() {
    $key = "barfoo";
    $tokenGen = new Services_FirebaseTokenGenerator($key);
    $notBefore = new DateTime("now", new DateTimeZone('America/Los_Angeles'));
    $token = $tokenGen->createToken(null, array("notBefore" => $notBefore));
    
    $data = JWT::decode($token, $key);
    $this->assertEquals($notBefore->getTimestamp(), $data->nbf);
  }
}

?>
