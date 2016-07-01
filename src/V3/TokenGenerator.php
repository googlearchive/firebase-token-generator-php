<?php


namespace Firebase\Token\V3;

use Firebase\JWT\JWT;

final class TokenGenerator
{
    const MAX_EXPIRATION_TIME = 3600;
    const MAX_UID_LENGTH = 36;

    private static $reservedClaims = [
        'acr', 'amr', 'at_hash', 'aud', 'auth_time', 'azp', 'cnf', 'c_hash',
        'exp', 'firebase', 'iat', 'iss', 'jti', 'nbf', 'nonce', 'sub',
    ];

    /**
     * @var ServiceAccount
     */
    private $serviceAccount;

    /**
     * @var int
     */
    private $isDebugEnabled;

    /**
     * @param ServiceAccount $serviceAccount The project's service account.
     * @param bool $enableDebug If true, enables the debug mode.
     */
    public function __construct(ServiceAccount $serviceAccount, $enableDebug = false)
    {
        $this->serviceAccount = $serviceAccount;
        $this->isDebugEnabled = (bool) $enableDebug;
    }

    /**
     * Returns a new instance with enabled debug mode.
     *
     * @return TokenGenerator
     */
    public function withEnabledDebug()
    {
        return new self($this->serviceAccount, true);
    }

    /**
     * Returns a new instance with disabled debug mode.
     *
     * @return TokenGenerator
     */
    public function withDisabledDebug()
    {
        return new self($this->serviceAccount, false);
    }

    /**
     * Returns whether the generator runs in debug mode or not.
     *
     * @return int
     */
    public function isDebugEnabled()
    {
        return $this->isDebugEnabled;
    }

    /**
     * Returns a JWT token.
     *
     * @param string $uid The unique identifier of the signed-in user.
     * @param array $claims Optional custom claims to include in the Security Rules auth / request.auth variables.
     * @param int $expirationTime The time, in seconds since the UNIX epoch, at which the token expires.
     *
     * @throws \InvalidArgumentException
     *
     * @return string The JWT Token.
     */
    public function createCustomToken($uid, array $claims = [], $expirationTime = self::MAX_EXPIRATION_TIME)
    {
        if (!$uid || !is_string($uid) || strlen($uid) > self::MAX_UID_LENGTH) {
            throw new \InvalidArgumentException(
                sprintf('The unique identifier must be a string and 1-%d characters long.', self::MAX_UID_LENGTH)
            );
        }

        if (!is_int($expirationTime) || $expirationTime > self::MAX_EXPIRATION_TIME) {
            throw new \InvalidArgumentException(
                sprintf('The expiration time must be an integer with a maximum of %d.', self::MAX_EXPIRATION_TIME)
            );
        }

        if ($invalidClaims = array_intersect(self::$reservedClaims, array_keys($claims))) {
            throw new \InvalidArgumentException(
                sprintf('"%s" is a/are reserved claim(s) and must not be used.', implode('", "', $invalidClaims))
            );
        }

        $now = time();

        $payload = [
            'iss' => $this->serviceAccount->getClientEmail(),
            'sub' => $this->serviceAccount->getClientEmail(),
            'aud' => 'https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit',
            'iat' => $now,
            'exp' => $now + $expirationTime,
            'uid' => $uid,
            'claims' => $claims,
        ];

        if ($this->isDebugEnabled === true) {
            $payload['debug'] = true;
        }

        return JWT::encode($payload, $this->serviceAccount->getPrivateKey(), 'RS256');
    }
}
