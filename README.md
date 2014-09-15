# Firebase Token Generator - PHP

[Firebase Custom Login](https://www.firebase.com/docs/web/guide/simple-login/custom.html)
gives you complete control over user authentication by allowing you to authenticate users
with secure JSON Web Tokens (JWTs). The auth payload stored in those tokens is available
for use in your Firebase [security rules](https://www.firebase.com/docs/security/api/rule/).
This is a token generator library for PHP which allows you to easily create those JWTs.


## Dependencies

The Firebase PHP token generator library depends on [PHP-JWT](https://github.com/firebase/php-jwt).


## A Note About Security

**IMPORTANT:** Because token generation requires your Firebase Secret, you should only generate
tokens on *trusted servers*. Never embed your Firebase Secret directly into your application and
never share your Firebase Secret with a connected client.


## Generating Tokens

To generate tokens, you'll need your Firebase Secret which you can find by entering your Firebase
URL into a browser and clicking the "Secrets" tab on the left-hand navigation menu.

Once you've downloaded the library and grabbed your Firebase Secret, you can generate a token with
this snippet of PHP code:

```php
<?php
  include_once "FirebaseToken.php";

  $tokenGen = new Services_FirebaseTokenGenerator("<YOUR_FIREBASE_SECRET>");
  $token = $tokenGen->createToken(array("uid" => "exampleID"));
?>
```

The payload passed to `createToken()` is made available for use within your
security rules via the [`auth` variable](https://www.firebase.com/docs/security/api/rule/auth.html).
This is how you pass trusted authentication details (e.g. the client's user ID)
to your Firebase security rules. The payload can contain any data of your
choosing, however it must contain a "uid" key, which must be a string of less
than 256 characters. The generated token must be less than 1024 characters in
total.


## Token Options

A second `options` argument can be passed to `createToken()` to modify how Firebase treats the
token. Available options are:

* **expires** (number or DateTime) - A timestamp (as number of seconds since the epoch) or a `DateTime`
denoting the time after which this token should no longer be valid.

* **notBefore** (number or DateTime) - A timestamp (as number of seconds since the epoch) or a `DateTime`
denoting the time before which this token should be rejected by the server.

* **admin** (boolean) - Set to `True` if you want to disable all security rules for this client.
This will provide the client with read and write access to your entire Firebase.

* **debug** (boolean) - Set to `True` to enable debug output from your security rules. You should
generally *not* leave this set to `True` in production (as it slows down the rules implementation
and gives your users visibility into your rules), but it can be helpful for debugging.

Here is an example of how to use the second `options` argument:

```php
<?php
  include_once "FirebaseToken.php";

  $tokenGen = new Services_FirebaseTokenGenerator("<YOUR_FIREBASE_SECRET>");
  $token = $tokenGen->createToken(array("uid" => "exampleID"), array("admin" => True));
?>
```
