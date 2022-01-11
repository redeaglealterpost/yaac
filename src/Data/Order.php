<?php


namespace Afosto\Acme\Data;

class Order
{
    const STATUS_PENDING = 'pending';
    const STATUS_READY = 'ready';
    const STATUS_VALID = 'valid';
    const STATUS_PROCESSING = 'processing';

    const STATUS_INVALID = 'invalid';

    /**
     * @var string
     */
    protected $url;

    /**
     * status (required, string):  The status of this order.  Possible
     * values are "pending", "ready", "processing", "valid", and
     * "invalid".  See Section 7.1.6.
     *
     * @var string
     */
    protected $status;

    /**
     * @var \DateTime
     */
    protected $expiresAt;

    /**
     * @var array
     */
    protected $identifiers;

    /**
     * @var array
     */
    protected $authorizations;

    /**
     * @var string
     */
    protected $finalizeURL;

    /**
     * @var array
     */
    protected $domains;

    /**
     * @var string|null
     */
    protected $certificateUrl;

    /**
     * Order constructor.
     *
     * @param array $domains
     * @param string $url
     * @param string $status
     * @param string $expiresAt
     * @param array $identifiers
     * @param array $authorizations
     * @param string $finalizeURL
     * @param ?string $certificateUrl
     * @throws \Exception
     */
    public function __construct(
        array   $domains,
        string  $url,
        string  $status,
        string  $expiresAt,
        array   $identifiers,
        array   $authorizations,
        string  $finalizeURL,
        ?string $certificateUrl = null
    )
    {
        //Handle the microtime date format
        if (strpos($expiresAt, '.') !== false) {
            $expiresAt = substr($expiresAt, 0, strpos($expiresAt, '.')) . 'Z';
        }
        $this->domains = $domains;
        $this->url = $url;
        $this->status = $status;
        $this->expiresAt = (new \DateTime())->setTimestamp(strtotime($expiresAt));
        $this->identifiers = $identifiers;
        $this->authorizations = $authorizations;
        $this->finalizeURL = $finalizeURL;
        $this->certificateUrl = $certificateUrl;
    }

    /**
     * Returns the order number
     * @return string
     */
    public function getId(): string
    {
        return substr($this->url, strrpos($this->url, '/') + 1);
    }

    /**
     * Returns the order URL
     * @return string
     */
    public function getURL(): string
    {
        return $this->url;
    }

    /**
     * Return set of authorizations for the order
     * @return string[]
     */
    public function getAuthorizationURLs(): array
    {
        return $this->authorizations;
    }

    /**
     * Returns order status
     * @return string
     */
    public function getStatus(): string
    {
        return $this->status;
    }

    /**
     * Returns expires at
     * @return \DateTime
     */
    public function getExpiresAt(): \DateTime
    {
        return $this->expiresAt;
    }

    /**
     * Returns domains as identifiers
     * @return array
     */
    public function getIdentifiers(): array
    {
        return $this->identifiers;
    }

    /**
     * Returns url
     * @return string
     */
    public function getFinalizeURL(): string
    {
        return $this->finalizeURL;
    }

    /**
     * Returns domains for the order
     * @return array
     */
    public function getDomains(): array
    {
        return $this->domains;
    }

    public function getCertificateUrl(): ?string
    {
        return $this->certificateUrl;
    }

    public function isReady(): bool
    {
        return $this->status === self::STATUS_READY;
    }

    public function isValid(): bool
    {
        return $this->status === self::STATUS_VALID;
    }

    public function isProcessing(): bool
    {
        return $this->status === self::STATUS_PROCESSING;
    }

    public function isInvalid(): bool
    {
        return $this->status === self::STATUS_INVALID;
    }

    public function updateWith(Order $order): void
    {
        if ($order->getId() !== $this->getId()) {
            throw new \InvalidArgumentException('There is different orders.');
        }

        $this->status = $order->getStatus();
        $this->certificateUrl = $order->getCertificateUrl();
        $this->authorizations = $order->getAuthorizationURLs();
        $this->finalizeURL = $order->getFinalizeURL();
        $this->expiresAt = $order->getExpiresAt();
    }
}
