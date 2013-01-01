<?php

include_once 'JWT.php';

class FirebaseTokenGenerator
{
    private $version = 0;

    /**
     * Example usage:
     *     $tokenGen = new FirebaseTokenGenerator("0014ae3b1ded44de9d9f6fc60dfd1c64");
     *     $tokenGen->createToken(array("id" => "foo", "bar" => "baz"));
     *
     * @access  public
     * @param   string       $secret   The API secret for the Firebase you
     *                                 want to generate an auth token for.
     */
    public function __construct($secret)
    {
        if (!is_string($secret)) {
            throw new UnexpectedValueException("Invalid secret provided");
        }
        $this->secret = $secret;
    }

    /**
     * @access  public
     * @param   array|object $data     An object or array of data you wish
     *                                 to associate with the token. It will
     *                                 be available as the variable "auth" in
     *                                 the Firebase rules engine.
     * @param   boolean      $admin    Optional, defaults to false. Set to true
     *                                 if you want this token to bypass all
     *                                 security rules.
     * @param   boolean      $debug    Optional, defaults to false. Set to true
     *                                 if you want to enable debug output from
     *                                 your security rules.
     *
     * @return  string       A Firebase auth token.
     */
    public function createToken($data, $admin = false, $debug = false)
    {
        // If $data is JSONifiable, let it pass.
        $json = json_encode($data);
        if (function_exists("json_last_error") && $errno = json_last_error()) {
            $this->handleJSONError($errno);
        } else if ($json === "null" && $data !== null) {
            throw new UnexpectedValueException("Data is not valid JSON");
        }

        $claims = array(
            "d" => $data,
            "v" => $this->version,
            // Firebase expects iat in milliseconds.
            "iat" => time() * 1000
        );

        if ($admin === true) {
          $claims["admin"] = true;
        }
        if ($debug === true) {
          $claims["debug"] = true;
        }

        return JWT::encode($claims, $this->secret, "HS256");
    }

    /**
     * @access  private
     * @param   int          $errno    An error number from json_last_error()
     *
     * @return  void
     */
    private static function handleJsonError($errno)
    {
        $messages = array(
            JSON_ERROR_DEPTH => 'Maximum stack depth exceeded',
            JSON_ERROR_CTRL_CHAR => 'Unexpected control character found',
            JSON_ERROR_SYNTAX => 'Syntax error, malformed JSON'
        );
        throw new UnexpectedValueException(isset($messages[$errno])
            ? $messages[$errno]
            : 'Unknown JSON error: ' . $errno
        );
    }
}

?>