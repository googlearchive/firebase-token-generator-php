<?php

namespace Firebase\Token\V3;

/**
 * Represents a Google Service Account.
 *
 * Only the fields needed for the authentication with Firebase are required.
 */
final class ServiceAccount
{
    /**
     * @var string
     */
    private $clientEmail;

    /**
     * @var string
     */
    private $privateKey;

    /**
     * @param string $clientEmail The project's service account email address.
     * @param string $privateKey The project's private key.
     *
     * @throws \InvalidArgumentException If the provided email address is not valid-
     */
    public function __construct($clientEmail, $privateKey)
    {
        if (!filter_var($clientEmail, FILTER_VALIDATE_EMAIL)) {
            throw new \InvalidArgumentException(
                sprintf('Invalid service account email "%s".', (string) $clientEmail)
            );
        }

        $this->clientEmail = $clientEmail;
        $this->privateKey = $privateKey;
    }

    /**
     * Creates a Service Account instance from the file at the provided path.
     *
     * @param string $path The path to the key file.
     *
     * @throws \InvalidArgumentException If the key file is not readable or invalid.
     *
     * @return ServiceAccount
     */
    public static function fromKeyFile($path)
    {
        if (!is_file($path) || !is_readable($path)) {
            throw new \InvalidArgumentException(sprintf('%s is not readable.', $path));
        }

        $data = json_decode(file_get_contents($path), true);

        if (!$data) {
            throw new \InvalidArgumentException(sprintf('%s does not contain a valid JSON string.', $path));
        }

        foreach (['client_email', 'private_key'] as $key) {
            if (!array_key_exists($key, $data)) {
                throw new \InvalidArgumentException(sprintf('Missing key "%s".', $key));
            }
        }

        return new self($data['client_email'], $data['private_key']);
    }

    /**
     * Returns the project's service account email address.
     *
     * @return string
     */
    public function getClientEmail()
    {
        return $this->clientEmail;
    }

    /**
     * Returns the project's private key.
     *
     * @return string
     */
    public function getPrivateKey()
    {
        return $this->privateKey;
    }
}
