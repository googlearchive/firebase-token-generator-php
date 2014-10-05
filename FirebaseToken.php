<?php

$jwt_filename = dirname(__FILE__) . '/JWT.php';

if (!file_exists($jwt_filename)) {
    // try Composer autoload
    $jwt_filename = dirname(__FILE__) . '/vendor/autoload.php';
}

if (file_exists($jwt_filename)) {
    include_once $jwt_filename;
}

class Services_FirebaseTokenGenerator
{
    private $version = 0;

    /**
     * Example usage:
     *     $tokenGen = new Services_FirebaseTokenGenerator("0014ae3b1ded44de9d9f6fc60dfd1c64");
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
     * @param   object       $options  Optional. An associative array with
     *                                 the developer supplied options for this
     *                                 token. The following keys are recognized:
     *
     *                                   'admin': Set to true if you want this
     *                                   token to bypass all security rules.
     *                                   Defaults to false.
     *
     *                                   'debug': Set to true if you want to
     *                                   enable debug output from your security
     *                                   rules.
     *
     *                                   'expires': Set to a number (seconds
     *                                   since epoch) or a DateTime object that
     *                                   specifies the time at which the token
     *                                   should expire.
     *
     *                                   'notBefore': Set to a number (seconds
     *                                   since epoch) or a DateTime object that
     *                                   specifies the time before which the
     *                                   should be rejected by the server.
     *
     *
     * @return  string       A Firebase auth token.
     */
    public function createToken($data, $options = null)
    {
        $funcName = 'Services_FirebaseTokenGenerator->createToken';

        // If $data is JSONifiable, let it pass.
        $json = json_encode($data);
        if (function_exists("json_last_error") && $errno = json_last_error()) {
            $this->handleJSONError($errno);
        } else if ($json === "null" && $data !== null) {
            throw new UnexpectedValueException("Data is not valid JSON");
        } else if (empty($data) && empty($options)) {
            throw new Exception($funcName + ": data is empty and no options are set.  This token will have no effect on Firebase.");
        }

        $claims = array();
        if (is_array($options)) {
            $claims = $this->_processOptions($options);
        }

        $this->_validateData($funcName, $data, (isset($claims['admin']) && ($claims["admin"] == true)));

        $claims["d"] = $data;
        $claims["v"] = $this->version;
        $claims["iat"] = time();

        $token = JWT::encode($claims, $this->secret, "HS256");
        if (strlen($token) > 1024) {
            throw new Exception($funcName + ": generated token is too large.  Token cannot be larger than 1024 bytes.");
        }
        return $token;
    }

    /**
     * Parses provided options into a claims object.
     *
     * @param object $options Options as passed by the developer to createToken.
     *
     * @return array A claims array in which the options are stored.
     */
    private static function _processOptions($options) {
        $claims = array();
        foreach ($options as $key => $value) {
            switch ($key) {
                case "admin":
                    $claims["admin"] = $value;
                    break;
                case "debug":
                    $claims["debug"] = $value;
                    break;
                case "expires":
                case "notBefore":
                    $code = "exp";
                    if ($key == "notBefore") {
                        $code = "nbf";
                    }
                    switch (gettype($value)) {
                        case "integer":
                            $claims[$code] = $value;
                            break;
                        case "object":
                            if ($value instanceof DateTime) {
                                $claims[$code] = $value->getTimestamp();
                            } else {
                                throw new UnexpectedValueException(
                                    "Provided " + $key +
                                    " option is not a DateTime object");
                            }
                            break;
                        default:
                            throw new UnexpectedValueException(
                                "Provided " + $key +
                                " option is invalid " + $value);
                    }
                    break;
                default:
                    throw new UnexpectedValueException(
                        "Invalid key " + $key + " provided in options");
            }
        }
        return $claims;
    }

    /**
     * Validates provided data object, throwing Exceptions where necessary.
     *
     * @param string $funcName the function name string for error message reporting.
     * @param array $data the token data to be validated.
     * @param boolean $isAdminToken whether the admin flag has been set.
     */
     private static function _validateData($funcName, $data, $isAdminToken) {
        if (!is_null($data) && !is_array($data)) {
            throw new Exception($funcName + ": data must be null or an associative array of token data.");
        }
        $containsUID = (is_array($data) && array_key_exists("uid", $data));
        if ((!$containsUID && !$isAdminToken) || ($containsUID && !is_string($data["uid"]))) {
            throw new Exception($funcName + ": data must contain a \"uid\" key that must be a string.");
        } else if ($containsUID && (strlen($data["uid"]) > 256)) {
            throw new Exception($funcName + ": data must contain a \"uid\" key that must not be longer than 256 bytes.");
        }
    }

    /**
     * @access  private
     * @param   int          $errno    An error number from json_last_error()
     *
     * @return  void
     */
    private static function handleJSONError($errno)
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
