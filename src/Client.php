<?php

namespace Afosto\Acme;

use Afosto\Acme\Data\Account;
use Afosto\Acme\Data\Authorization;
use Afosto\Acme\Data\Certificate;
use Afosto\Acme\Data\Challenge;
use Afosto\Acme\Data\Order;
use Afosto\Acme\Exception\NotReadyOrderException;
use Afosto\Acme\Exception\UnrecoverableOrderException;
use GuzzleHttp\Client as GuzzleHttpClient;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Uri;
use GuzzleHttp\Psr7\Utils;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\ResponseInterface;

class Client
{
    const OPTION_USERNAME = 'username';
    const OPTION_ACCOUNT_PRIVATE_KEY_PEM = 'account_private_key_pem';
    const OPTION_MODE = 'mode';
    const OPTION_SOURCE_IP = 'source_ip';

    /**
     * Live url
     */
    const DIRECTORY_LIVE = 'https://acme-v02.api.letsencrypt.org/directory';

    /**
     * Staging url
     */
    const DIRECTORY_STAGING = 'https://acme-staging-v02.api.letsencrypt.org/directory';

    /**
     * Flag for production
     */
    const MODE_LIVE = 'live';

    /**
     * Flag for staging
     */
    const MODE_STAGING = 'staging';

    /**
     * New account directory
     */
    const DIRECTORY_NEW_ACCOUNT = 'newAccount';

    /**
     * Nonce directory
     */
    const DIRECTORY_NEW_NONCE = 'newNonce';

    /**
     * Order certificate directory
     */
    const DIRECTORY_NEW_ORDER = 'newOrder';

    /**
     * Http validation
     */
    const VALIDATION_HTTP = 'http-01';

    /**
     * DNS validation
     */
    const VALIDATION_DNS = 'dns-01';

    /**
     * @var string
     */
    protected $nonce;

    /**
     * @var Account
     */
    protected $account;

    /**
     * @var array
     */
    protected $privateKeyDetails;

    /**
     * @var string
     */
    protected $accountKey;

    /**
     * @var string
     */
    protected $accountPrivateKeyPem;

    /**
     * @var array
     */
    protected $directories = [];

    /**
     * @var array
     */
    protected $header = [];

    /**
     * @var string
     */
    protected $digest;

    /**
     * @var ClientInterface
     */
    protected $acmeHttpClient;

    /**
     * @var array
     */
    protected $config;

    /**
     * @var RequestFactoryInterface
     */
    protected $requestFactory;

    /**
     * @var ClientInterface
     */
    protected $selfTestHttpClient;

    /**
     * @var ClientInterface
     */
    protected $selfTestDNSClient;

    /**
     * @param string $mode (required) The mode for ACME (production / staging)
     * @param string $accountPrivateKeyPem (required) Account private key in pem format.
     * @param string $username (required) The acme username
     * @param string|null $sourceIp (optional) The source IP for Guzzle (via curl.options) to bind to (defaults to 0.0.0.0 [OS default])
     * @type ClientInterface $acmeHttpClient (optional)
     * @type ClientInterface $selfTestHttpClient (optional)
     * @type ClientInterface $selfTestDNSClient (optional)
     * @type RequestFactoryInterface $requestFactory (optional)
     * }
     * @throws ClientExceptionInterface
     */
    public function __construct(
        string                  $mode,
        string                  $username,
        string                  $accountPrivateKeyPem,
        string                  $sourceIp = null,
        ClientInterface         $acmeHttpClient = null,
        ClientInterface         $selfTestHttpClient = null,
        ClientInterface         $selfTestDNSClient = null,
        RequestFactoryInterface $requestFactory = null
    )
    {
        $this->config = [
            self::OPTION_MODE                    => $mode,
            self::OPTION_USERNAME                => $username,
            self::OPTION_ACCOUNT_PRIVATE_KEY_PEM => $accountPrivateKeyPem,
            self::OPTION_SOURCE_IP               => $sourceIp
        ];

        $this->acmeHttpClient = $acmeHttpClient ?? $this->createHttpClient();
        $this->requestFactory = $requestFactory ?? new HttpFactory();
        $this->selfTestDNSClient = $selfTestDNSClient ?? $this->createSelfTestDNSClient();
        $this->selfTestHttpClient = $selfTestHttpClient ?? $this->createSelfTestHttpClient();

        $this->init();
    }

    /**
     * Get an existing order by ID
     *
     * @throws ClientExceptionInterface
     * @throws \Exception
     */
    public function getOrder(string $id): Order
    {
        $url = str_replace('new-order', 'order', $this->getUrl(self::DIRECTORY_NEW_ORDER));
        $url = $url . '/' . $this->getAccount()->getId() . '/' . $id;
        $response = $this->request($url, $this->signPayloadKid(null, $url));
        $data = json_decode((string)$response->getBody(), true);

        $domains = [];
        foreach ($data['identifiers'] as $identifier) {
            $domains[] = $identifier['value'];
        }

        return new Order(
            $domains,
            $url,
            $data['status'],
            $data['expires'],
            $data['identifiers'],
            $data['authorizations'],
            $data['finalize'],
            $data['certificate'] ?? null
        );
    }

    public function refreshOrder(Order $order): void
    {
        $order->updateWith($this->getOrder($order->getId()));
    }

    /**
     * Create a new order
     *
     * @throws \Exception
     * @throws ClientExceptionInterface
     */
    public function createOrder(array $domains): Order
    {
        $identifiers = [];
        foreach ($domains as $domain) {
            $identifiers[] =
                [
                    'type'  => 'dns',
                    'value' => $domain,
                ];
        }

        $url = $this->getUrl(self::DIRECTORY_NEW_ORDER);
        $response = $this->request($url, $this->signPayloadKid(
            [
                'identifiers' => $identifiers,
            ],
            $url
        ));

        $data = json_decode((string)$response->getBody(), true);

        return new Order(
            $domains,
            $response->getHeaderLine('location'),
            $data['status'],
            $data['expires'],
            $data['identifiers'],
            $data['authorizations'],
            $data['finalize'],
            null
        );
    }

    /**
     * Obtain authorizations
     *
     * @return array|Authorization[]
     * @throws \Exception
     * @throws ClientExceptionInterface
     */
    public function authorize(Order $order): array
    {
        $authorizations = [];
        foreach ($order->getAuthorizationURLs() as $authorizationURL) {
            $response = $this->request(
                $authorizationURL,
                $this->signPayloadKid(null, $authorizationURL)
            );
            $data = json_decode((string)$response->getBody(), true);
            $authorization = new Authorization($data['identifier']['value'], $data['expires'], $this->getDigest());

            foreach ($data['challenges'] as $challengeData) {
                $challenge = new Challenge(
                    $authorizationURL,
                    $challengeData['type'],
                    $challengeData['status'],
                    $challengeData['url'],
                    $challengeData['token']
                );
                $authorization->addChallenge($challenge);
            }
            $authorizations[] = $authorization;
        }

        return $authorizations;
    }

    /**
     * Run a self-test for the authorization
     *
     * @throws ClientExceptionInterface
     */
    public function selfTest(Authorization $authorization, string $type = self::VALIDATION_HTTP, int $maxAttempts = 15): bool
    {
        switch ($type) {
            case self::VALIDATION_HTTP:
                return $this->selfHttpTest($authorization, $maxAttempts);
            case self::VALIDATION_DNS:
                return $this->selfDNSTest($authorization, $maxAttempts);
            default:
                throw new \InvalidArgumentException(
                    sprintf('$type should be one of %s, %s given', join(', ', [self::VALIDATION_DNS, self::VALIDATION_HTTP]), $type)
                );
        }
    }

    /**
     * Validate a challenge
     *
     * @param Challenge $challenge
     * @param int $maxAttempts
     * @return bool
     * @throws \Exception
     * @throws ClientExceptionInterface
     */
    public function validate(Challenge $challenge, int $maxAttempts = 15): bool
    {
        $this->request(
            $challenge->getUrl(),
            $this->signPayloadKid([
                'keyAuthorization' => $challenge->getToken() . '.' . $this->getDigest()
            ], $challenge->getUrl())
        );

        $data = [];

        do {
            $response = $this->request(
                $challenge->getAuthorizationURL(),
                $this->signPayloadKid(null, $challenge->getAuthorizationURL())
            );
            $data = json_decode((string)$response->getBody(), true);
            if ($maxAttempts > 1 && $data['status'] != 'valid') {
                sleep(ceil(15 / $maxAttempts));
            }
            $maxAttempts--;
        } while ($maxAttempts > 0 && $data['status'] != 'valid');

        return (isset($data['status']) && $data['status'] == 'valid');
    }

    /**
     * @throws ClientExceptionInterface
     * @throws \Exception
     */
    public function finalize(Order $order, string $privateKey): void
    {
        if (!$order->isReady()) {
            throw new NotReadyOrderException($order);
        }

        $csr = Helper::getCsr($order->getDomains(), $privateKey);
        $der = Helper::toDer($csr);

        $response = $this->request(
            $order->getFinalizeURL(),
            $this->signPayloadKid(
                ['csr' => Helper::toSafeString($der)],
                $order->getFinalizeURL()
            )
        );

        $data = json_decode($response->getBody()->getContents(), true);

        if (Order::STATUS_INVALID === $data['status'] || isset($data['error'])) {
            throw new UnrecoverableOrderException(
                $order,
                sprintf('Error while finalization: %s', json_encode($data['error']))
            );
        }

        $order->updateWith(new Order(
            $order->getDomains(),
            $order->getURL(),
            $data['status'],
            $data['expires'],
            $data['identifiers'],
            $data['authorizations'],
            $data['finalize'],
            $data['certificate'] ?? null
        ));
    }

    /**
     * Return a certificate
     *
     * @throws \Exception
     * @throws ClientExceptionInterface
     */
    public function getCertificate(Order $order, string $privateKey = null, int $maxProcessingTime = 60): Certificate
    {
        if (!$order->isValid() && !$order->isReady()) {
            throw new NotReadyOrderException(
                $order,
                'Order is not ready yet. Check authorizations or just wait for a while.'
            );
        }

        if (null === $privateKey && $order->isValid()) {
            throw new UnrecoverableOrderException(
                $order,
                'Can\'t retrieve certificate for finalized order without private key used for finalization. Restart order.'
            );
        }

        $privateKey = $privateKey ?? Helper::getNewKey();

        if ($order->isReady()) {
            $this->finalize($order, $privateKey);
        }

        $sleep = 0;
        while ($order->isProcessing() && $sleep < $maxProcessingTime) {
            $sleep += 5;
            sleep(5);
            $this->refreshOrder($order);
        }

        if ($order->isProcessing()) {
            throw new NotReadyOrderException(
                $order,
                'Order freeze in processing status. Check authorizations or just wait for a while.'
            );
        }

        if (!$order->isValid()) {
            throw new UnrecoverableOrderException(
                $order,
                'Order has invalid status. '
            );
        }

        $certificateResponse = $this->request(
            $order->getCertificateUrl(),
            $this->signPayloadKid(null, $order->getCertificateUrl())
        );

        $chain = $str = preg_replace('/^[ \t]*[\r\n]+/m', '', (string)$certificateResponse->getBody());
        return new Certificate($privateKey, $chain);
    }

    /**
     * Return LE account information
     *
     * @return Account
     * @throws \Exception
     * @throws ClientExceptionInterface
     */
    public function getAccount(): Account
    {
        $response = $this->request(
            $this->getUrl(self::DIRECTORY_NEW_ACCOUNT),
            $this->signPayloadJWK(
                [
                    'onlyReturnExisting' => true,
                ],
                $this->getUrl(self::DIRECTORY_NEW_ACCOUNT)
            )
        );

        $data = json_decode((string)$response->getBody(), true);
        $accountURL = $response->getHeaderLine('Location');
        $date = (new \DateTime())->setTimestamp(strtotime($data['createdAt']));
        return new Account($data['contact'], $date, ($data['status'] == 'valid'), $data['initialIp'], $accountURL);
    }

    /**
     * Returns the ACME api configured Guzzle Client
     */
    protected function createHttpClient(): ClientInterface
    {
        $isLive = $this->getOption(self::OPTION_MODE) == self::MODE_LIVE;

        $config = [
            'base_uri' => $isLive ? self::DIRECTORY_LIVE : self::DIRECTORY_STAGING,
        ];

        if ($this->getOption(self::OPTION_SOURCE_IP)) {
            $config['curl.options']['CURLOPT_INTERFACE'] = $this->getOption(self::OPTION_SOURCE_IP);
        }

        return new GuzzleHttpClient($config);
    }

    /**
     * Returns a Guzzle Client configured for self test
     *
     * @return GuzzleHttpClient
     */
    protected function createSelfTestHttpClient(): GuzzleHttpClient
    {
        return new GuzzleHttpClient([
            'verify'          => false,
            'timeout'         => 10,
            'connect_timeout' => 3,
            'allow_redirects' => true,
        ]);
    }

    /**
     * Self HTTP test
     * @param Authorization $authorization
     * @param $maxAttempts
     * @return bool
     * @throws ClientExceptionInterface
     */
    protected function selfHttpTest(Authorization $authorization, $maxAttempts): bool
    {
        $uriString = sprintf(
            'http://%s/.well-known/acme-challenge/%s',
            $authorization->getDomain(),
            $authorization->getFile()->getFilename()
        );

        $request = $this->requestFactory->createRequest('get', $uriString);

        do {
            $maxAttempts--;
            try {
                $response = $this->selfTestHttpClient->sendRequest($request);
                $contents = (string)$response->getBody();
                if ($contents == $authorization->getFile()->getContents()) {
                    return true;
                }
            } catch (RequestException $e) {
            }
        } while ($maxAttempts > 0);

        return false;
    }

    /**
     * Self DNS test client that uses Cloudflare's DNS API
     * @param Authorization $authorization
     * @param $maxAttempts
     * @return bool
     *
     * @throws ClientExceptionInterface
     */
    protected function selfDNSTest(Authorization $authorization, $maxAttempts): bool
    {
        $uri = Uri::fromParts([
            'path' => '/dns-query',
            'query' => sprintf('name=%s&type=TXT', $authorization->getTxtRecord()->getName())
        ]);

        $request = $this->requestFactory->createRequest('get', $uri);

        do {
            $response = $this->selfTestDNSClient->sendRequest($request);
            $data = json_decode((string)$response->getBody(), true);
            if (isset($data['Answer'])) {
                foreach ($data['Answer'] as $result) {
                    if (trim($result['data'], "\"") == $authorization->getTxtRecord()->getValue()) {
                        return true;
                    }
                }
            }
            if ($maxAttempts > 1) {
                sleep(ceil(45 / $maxAttempts));
            }
            $maxAttempts--;
        } while ($maxAttempts > 0);

        return false;
    }

    /**
     * Return the preconfigured client to call Cloudflare's DNS API
     */
    protected function createSelfTestDNSClient(): GuzzleHttpClient
    {
        return new GuzzleHttpClient([
            'base_uri'        => 'https://cloudflare-dns.com',
            'connect_timeout' => 10,
            'headers'         => [
                'Accept' => 'application/dns-json',
            ],
        ]);
    }

    /**
     * Initialize the client
     *
     * @throws ClientExceptionInterface
     * @throws \Exception
     */
    protected function init()
    {
        //Load the directories from the LE api
        $response = $this->acmeHttpClient->sendRequest($this->requestFactory->createRequest('get', '/directory'));
        $result = json_decode((string)$response->getBody(), true);
        $this->directories = $result;

        //Prepare LE account
        $this->loadKeys();
        $this->tosAgree();
        $this->account = $this->getAccount();
    }

    /**
     * Load the keys in memory
     */
    protected function loadKeys(): void
    {
        $this->accountPrivateKeyPem = $this->getOption(self::OPTION_ACCOUNT_PRIVATE_KEY_PEM, Helper::getNewKey());

        $privateKey = openssl_pkey_get_private($this->accountPrivateKeyPem);
        $this->privateKeyDetails = openssl_pkey_get_details($privateKey);
    }

    /**
     * Agree to the terms of service
     *
     * @throws \Exception
     * @throws ClientExceptionInterface
     */
    protected function tosAgree()
    {
        $this->request(
            $this->getUrl(self::DIRECTORY_NEW_ACCOUNT),
            $this->signPayloadJWK(
                [
                    'contact'              => [
                        'mailto:' . $this->getOption(self::OPTION_USERNAME),
                    ],
                    'termsOfServiceAgreed' => true,
                ],
                $this->getUrl(self::DIRECTORY_NEW_ACCOUNT)
            )
        );
    }

    /**
     * Get a defined option
     *
     * @param      $key
     * @param null $default
     *
     * @return mixed|null
     */
    protected function getOption($key, $default = null)
    {
        if (isset($this->config[$key])) {
            return $this->config[$key];
        }

        return $default;
    }

    /**
     * Get key fingerprint
     *
     * @return string
     * @throws \Exception
     */
    protected function getDigest(): string
    {
        if ($this->digest === null) {
            $this->digest = Helper::toSafeString(hash('sha256', json_encode($this->getJWKHeader()), true));
        }

        return $this->digest;
    }

    /**
     * Send a request to the LE API
     * @throws ClientExceptionInterface
     */
    protected function request($url, array $payload = [], string $method = 'POST'): ResponseInterface
    {
        $request = $this->requestFactory->createRequest($method, $url);
        $request->withBody(Utils::streamFor(json_encode($payload)));
        $request->withAddedHeader('Content-Type', 'application/jose+json');

        $response = $this->acmeHttpClient->sendRequest($request);
        $this->nonce = $response->getHeaderLine('replay-nonce');

        return $response;
    }

    /**
     * Get the LE directory path
     *
     * @param $directory
     *
     * @return mixed
     * @throws \Exception
     */
    protected function getUrl($directory): string
    {
        if (isset($this->directories[$directory])) {
            return $this->directories[$directory];
        }

        throw new \Exception('Invalid directory: ' . $directory . ' not listed');
    }

    /**
     * Get the key
     *
     * @return bool|resource|string
     * @throws \Exception
     */
    protected function getAccountKey()
    {
        if ($this->accountKey === null) {
            $this->accountKey = openssl_pkey_get_private($this->accountPrivateKeyPem);
        }

        if ($this->accountKey === false) {
            throw new \Exception('Invalid account key');
        }

        return $this->accountKey;
    }

    /**
     * Get the header
     *
     * @return array
     * @throws \Exception
     */
    protected function getJWKHeader(): array
    {
        return [
            'e'   => Helper::toSafeString(Helper::getKeyDetails($this->getAccountKey())['rsa']['e']),
            'kty' => 'RSA',
            'n'   => Helper::toSafeString(Helper::getKeyDetails($this->getAccountKey())['rsa']['n']),
        ];
    }

    /**
     * Get JWK envelope
     *
     * @param $url
     * @return array
     * @throws \Exception
     * @throws \Psr\Http\Client\ClientExceptionInterface
     */
    protected function getJWK($url): array
    {
        //Require a nonce to be available
        if ($this->nonce === null) {
            $response = $this->acmeHttpClient->sendRequest($this->requestFactory->createRequest('head', $this->directories[self::DIRECTORY_NEW_NONCE]));
            $this->nonce = $response->getHeaderLine('replay-nonce');
        }
        return [
            'alg'   => 'RS256',
            'jwk'   => $this->getJWKHeader(),
            'nonce' => $this->nonce,
            'url'   => $url
        ];
    }

    /**
     * Get KID envelope
     *
     * @param $url
     * @return array
     * @throws ClientExceptionInterface
     */
    protected function getKID($url): array
    {
        $response = $this->acmeHttpClient->sendRequest($this->requestFactory->createRequest('head', $this->directories[self::DIRECTORY_NEW_NONCE]));
        $nonce = $response->getHeaderLine('replay-nonce');

        return [
            "alg"   => "RS256",
            "kid"   => $this->account->getAccountURL(),
            "nonce" => $nonce,
            "url"   => $url
        ];
    }

    /**
     * Transform the payload to the JWS format
     *
     * @param $payload
     * @param $url
     * @return array
     * @throws \Exception
     * @throws ClientExceptionInterface
     */
    protected function signPayloadJWK($payload, $url): array
    {
        $payload = is_array($payload) ? str_replace('\\/', '/', json_encode($payload)) : '';
        $payload = Helper::toSafeString($payload);
        $protected = Helper::toSafeString(json_encode($this->getJWK($url)));

        $result = openssl_sign($protected . '.' . $payload, $signature, $this->getAccountKey(), "SHA256");

        if ($result === false) {
            throw new \Exception('Could not sign');
        }

        return [
            'protected' => $protected,
            'payload'   => $payload,
            'signature' => Helper::toSafeString($signature),
        ];
    }

    /**
     * Transform the payload to the KID format
     *
     * @param $payload
     * @param $url
     * @return array
     * @throws \Exception
     * @throws ClientExceptionInterface
     */
    protected function signPayloadKid($payload, $url): array
    {
        $payload = is_array($payload) ? str_replace('\\/', '/', json_encode($payload)) : '';
        $payload = Helper::toSafeString($payload);
        $protected = Helper::toSafeString(json_encode($this->getKID($url)));

        $result = openssl_sign($protected . '.' . $payload, $signature, $this->getAccountKey(), "SHA256");
        if ($result === false) {
            throw new \Exception('Could not sign');
        }

        return [
            'protected' => $protected,
            'payload'   => $payload,
            'signature' => Helper::toSafeString($signature),
        ];
    }
}
