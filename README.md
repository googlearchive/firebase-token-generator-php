Firebase Token Generator for PHP
================================
This library lets you easily generate
[authentication tokens](https://www.firebase.com/docs/security/authentication.html)
for accessing your Firebase securely. Depends on [PHP-JWT](https://github.com/firebase/php-jwt).

Example
-------
```php
<?php
  include_once "FirebaseToken.php";

  $secret = "0014ae3b1ded44de9d9f6fc60dfd1c64";
  $tokenGen = new Services_FirebaseTokenGenerator($secret);
  $token = $tokenGen->createToken(array("id" => "example"));

  // Get data only readable by auth.id = "example".
  $uri = "https://example.firebaseio.com/.json?auth=".$token;
  var_dump(file_get_contents($uri));
?>
```

License
-------
[MIT](http://firebase.mit-license.org/).
