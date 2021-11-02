<?php
namespace Schoolrunner\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use League\OAuth2\Client\Provider\AbstractProvider;
use Psr\Http\Message\ResponseInterface;
use Schoolrunner\OAuth2\Client\User\UserFactory;

/**
 * Clever OAuth2 Client
 */
class Clever extends AbstractProvider
{
    use BearerAuthorizationTrait;
    
    /**
     * @var UserFactory
     */
    protected $userFactory;
    
    /**
     * Constructs an OAuth 2.0 service provider.
     *
     * Override to add UserFactory
     *
     * @param array $options An array of options to set on this provider.
     *     Options include `clientId`, `clientSecret`, `redirectUri`, and `state`.
     *     Individual providers may introduce more options, as needed.
     * @param array $collaborators An array of collaborators that may be used to
     *     override this provider's default behavior. Collaborators include
     *     `grantFactory`, `requestFactory`, `httpClient`, and `randomFactory`.
     *     Individual providers may introduce more collaborators, as needed.
     */
    public function __construct(array $options = [], array $collaborators = [])
    {
        parent::__construct($options, $collaborators);
        
        if (empty($collaborators['userFactory'])) {
            $collaborators['userFactory'] = new UserFactory();
        }
        $this->setUserFactory($collaborators['userFactory']);
    }
    
    /**
     * Sets the instance of the user factory.
     *
     * @param  UserFactory $factory
     * @return self
     */
    public function setUserFactory(UserFactory $factory)
    {
        $this->userFactory = $factory;

        return $this;
    }

    /**
     * Returns the current user factory instance.
     *
     * @return UserFactory
     */
    public function getUserFactory()
    {
        return $this->userFactory;
    }
    
    /**
     * Get base authorization url
     * 
     * @return string Authorization url
     */
    public function getBaseAuthorizationUrl()
    {
        return 'https://clever.com/oauth/authorize';
    }

    /**
     * Get base access token url
     * 
     * @return string Access token url
     */
    public function getBaseAccessTokenUrl(array $params)
    {
        return 'https://clever.com/oauth/tokens';
    }
    
    /**
     * Get resource owner url
     * 
     * @return string Resource owner url
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token)
    {
        return 'https://api.clever.com/me';
    }
    
    /**
     * Get requested scopes
     * 
     * @return array Scopes
     */
    protected function getDefaultScopes()
    {
        return [
            'read:students',
            'read:teachers',
            'read:user_id'
        ];
    }
    
    /**
     * Returns all headers used by this provider for a request.
     *
     * Override to add a Basic Auth header needed when
     * requesting an access token from Clever
     *
     * @param  mixed|null $token object or string
     * @return array
     */
    public function getHeaders($token = null)
    {
        $headers = parent::getHeaders($token);

        if ($token == null)
        {
          $headers['authorization'] = 'Basic ' . base64_encode($this->clientId . ':' . $this->clientSecret);
        }

        return $headers;
    }
    
    /**
     * Check response for errors
     * 
     * @param  ResponseInterface $response Response object
     * @param  array             $data     Error Data
     * @return void
     */
    protected function checkResponse(ResponseInterface $response, $data)
    {
        if ($response->getStatusCode() >= 400)
        {
            $data = (is_array($data)) ? $data : json_decode($data, true);
            throw new IdentityProviderException($data['error_description'], $response->getStatusCode(), $data);
        }
    }
    
    /**
     * Create resource owner based on response
     * 
     * @param  array       $response Response data
     * @param  AccessToken $token    Access token
     * @return object                Resource owner
     */
    protected function createResourceOwner(array $response, AccessToken $token)
    {
        $className = $this
            ->getUserFactory()
            ->getClassNameForUserType($response['type']);

        return new $className($response, $token);
    }
}
