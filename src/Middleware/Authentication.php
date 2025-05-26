<?php

/**
 *  SFW2 - SimpleFrameWork
 *
 *  Copyright (C) 2025  Stefan Paproth
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as
 *  published by the Free Software Foundation, either version 3 of the
 *  License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program. If not, see <https://www.gnu.org/licenses/agpl.txt>.
 *
 */

declare(strict_types=1);

namespace SFW2\Authentication\Middleware;

use Exception;
use GuzzleHttp\Exception\GuzzleException;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use SFW2\Exception\HttpExceptions\Status4xx\HttpStatus403Forbidden;
use SFW2\Exception\HttpExceptions\Status4xx\HttpStatus422UnprocessableContent;
use SFW2\Interoperability\User\UserEntity;
use SFW2\Interoperability\User\UserRepositoryInterface;
use SFW2\Session\SessionInterface;

final class Authentication implements MiddlewareInterface
{
    public function __construct(
        private readonly SessionInterface        $session,
        private readonly UserRepositoryInterface $userRepository,
        private readonly AbstractProvider|null   $provider = null
    ) {
    }

    /**
     * @inheritDoc
     * @throws HttpStatus403Forbidden | HttpStatus422UnprocessableContent
     * @throws IdentityProviderException
     * @throws GuzzleException
     * @throws Exception
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        try {
            return $handler->handle($request);
        } catch (HttpStatus403Forbidden $e) {
            $userId = $this->session->getEntry(UserEntity::class);

            $user = $this->userRepository->loadUserById($userId);

            if ($user->isAuthenticated() || $this->provider === null) {
                throw $e;
            }

            $user = $this->oauthFlow();
            $this->session->setEntry(UserEntity::class, $user->getUserId());
            $this->session->regenerateSession();

            header("Location: /");
            die();
        }
    }

    /**
     * @throws GuzzleException
     * @throws HttpStatus422UnprocessableContent
     * @throws IdentityProviderException
     */
    private function oauthFlow(): UserEntity
    {

        if (!isset($_GET['code'])) {

            // Fetch the authorization URL from the provider; this returns the
            // urlAuthorize option and generates and applies any necessary parameters
            // (e.g. state).
            $authorizationUrl = $this->provider->getAuthorizationUrl();

            // Get the state generated for you and store it to the session.
            $this->session->setEntry('oauth2state', $this->provider->getState());

            // Optional, only required when PKCE is enabled.
            // Get the PKCE code generated for you and store it to the session.
            $this->session->setEntry('oauth2pkceCode', $this->provider->getPkceCode());

            // Redirect the user to the authorization URL.
            header('Location: ' . $authorizationUrl);
            exit;
        }

        // Check given state against previously stored one to mitigate CSRF attack
        if (
            empty($_GET['state']) || !$this->session->hasEntry('oauth2state') ||
            $_GET['state'] !== $this->session->getEntry('oauth2state')
        ) {
            $this->session->deleteEntry('oauth2state');
            throw new HttpStatus422UnprocessableContent('Invalid state');
        }

        // Optional, only required when PKCE is enabled.
        // Restore the PKCE code stored in the session.
        $this->provider->setPkceCode($this->session->getEntry('oauth2pkceCode'));

        // Try to get an access token using the authorization code grant.
        $tokens = $this->provider->getAccessToken('authorization_code', [
            'code' => $_GET['code']
        ]);

        $this->session->deleteEntry('oauth2state');
        $this->session->deleteEntry('oauth2pkceCode');

         // Using the access token, we may look up details about the
        // resource owner.
        $resourceOwner = $this->provider->getResourceOwner($tokens);

        $email = $resourceOwner->toArray()['user'];

        // We have an access token, which we may use in authenticated
        // requests against the service provider's API.
        echo 'Access Token: ' . $tokens->getToken() . "<br>";
        echo 'Refresh Token: ' . $tokens->getRefreshToken() . "<br>";
        echo 'Expired in: ' . $tokens->getExpires() . "<br>";
        echo 'Already expired? ' . ($tokens->hasExpired() ? 'expired' : 'not expired') . "<br>";
        /*
                // Using the access token, we may look up details about the
                // resource owner.
                $resourceOwner = $provider->getResourceOwner($tokens);

/*
        // The provider provides a way to get an authenticated API request for
        // the service, using the access token; it returns an object conforming
        // to Psr\Http\Message\RequestInterface.
        $request = $this->provider->getAuthenticatedRequest(
            'GET',
            'https://service.example.com/resource',
            $accessToken
        );
  */
        return $this->userRepository->loadUserByEmailAddress($email);
    }

}




