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
 *  along with this program. If not, see <http://www.gnu.org/licenses/agpl.txt>.
 *
 */

declare(strict_types=1);

namespace SFW2\Authentication\Controller;

use Exception;
use Psr\Container\ContainerExceptionInterface;
use Psr\Container\ContainerInterface;
use Psr\Container\NotFoundExceptionInterface;
use Psr\SimpleCache\InvalidArgumentException;
use SFW2\Authentication\PasskeyRepository;
use SFW2\Interoperability\User\UserEntity;
use SFW2\Interoperability\User\UserRepositoryInterface;
use SFW2\Database\DatabaseException;
use SFW2\Exception\HttpExceptions\Status4xx\HttpStatus400BadRequest;
use SFW2\Exception\HttpExceptions\Status4xx\HttpStatus403Forbidden;
use SFW2\Session\SessionInterface;

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use SFW2\Session\SessionSimpleCache;
use SFW2\Session\XSRFToken;
use Symfony\Component\Serializer\Encoder\JsonEncode;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Throwable;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialOptions;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;

final class Passkey
{
    private readonly string           $appName;
    private readonly string           $host;

    private readonly XSRFToken $challenge;

    /**
     * @throws ContainerExceptionInterface
     * @throws NotFoundExceptionInterface
     */
    public function __construct(
        private readonly SessionInterface        $session,
        private readonly UserRepositoryInterface $userRepository,
        private readonly PasskeyRepository       $passkeyRepository,
        private readonly ContainerInterface      $container
    ) {
        $this->challenge = new XSRFToken(new SessionSimpleCache($this->session, 'challenge'));;

        $this->appName = 'SSO';
        $this->host = $this->container->get('site.host');
    }

    /**
     * @throws DatabaseException
     * @throws Exception
     * @throws InvalidArgumentException
     */
    public function getRegistrationOptions(Request $request, Response $response, array $data): Response
    {
        $jsonObject = $this->serializeOptions($this->getCredentialCreationOptions($this->getUser()));
        $response->getBody()->write($jsonObject);
        return $response;
    }

    /**
     * @throws InvalidArgumentException
     */
    public function getAuthenticationOptions(Request $request, Response $response, array $data): Response
    {
        $publicKeyCredentialRequestOptions = PublicKeyCredentialRequestOptions::create($this->challenge->generateToken());
        $jsonObject = $this->serializeOptions($publicKeyCredentialRequestOptions);
        $response->getBody()->write($jsonObject);
        return $response;
    }

    /**
     * @throws Throwable
     */
    public function verifyRegistration(Request $request, Response $response, array $args): Response {
        $attestationStatementSupportManager = AttestationStatementSupportManager::create();
        $attestationStatementSupportManager->add(NoneAttestationStatementSupport::create());

        $factory = new WebauthnSerializerFactory($attestationStatementSupportManager);
        $serializer = $factory->create();

        $user = $this->getUser();
        $data = file_get_contents('php://input');

        /** @var PublicKeyCredential $publicKeyCredential */
        $publicKeyCredential = $serializer->deserialize($data, PublicKeyCredential::class, 'json');

        if (!$publicKeyCredential->response instanceof AuthenticatorAttestationResponse) {
            $response->getBody()->write(json_encode(['verified' => false, 'reason' => 'No attestation response']));
            return $response;
        }

        /** @var AuthenticatorAttestationResponse $attestationResponse */
        $attestationResponse = $publicKeyCredential->response;

        $csmFactory = new CeremonyStepManagerFactory();
        if($this->container->get('site.debugMode')) {
            // https://webauthn-doc.spomky-labs.com/v5.2/pure-php/advanced-behaviours/dealing-with-localhost#enabling-http-localhost-for-development
            $csmFactory->setAllowedOrigins([
                'http://localhost:8080',
            ]);
        }

        $creationCSM = $csmFactory->creationCeremony();

        $authenticatorAttestationResponseValidator = AuthenticatorAttestationResponseValidator::create($creationCSM);

        $publicKeyCredentialSource = $authenticatorAttestationResponseValidator->check(
            $attestationResponse,
            $this->getCredentialCreationOptions($user, $this->challenge->getToken()),
            $this->host
        );
        $this->passkeyRepository->saveCredentialSource($publicKeyCredentialSource);

        $response->getBody()->write(json_encode(['verified' => true]));
        return $response;
    }

    /**
     * @throws AuthenticatorResponseVerificationException
     * @throws InvalidArgumentException
     * @throws HttpStatus400BadRequest
     */
    public function verifyAuthentication(Request $request, Response $response, array $args): Response
    {
        // The manager will receive data to load and select the appropriate
        $attestationStatementSupportManager = AttestationStatementSupportManager::create();
        $attestationStatementSupportManager->add(NoneAttestationStatementSupport::create());

        $factory = new WebauthnSerializerFactory($attestationStatementSupportManager);
        $serializer = $factory->create();

        /** @var PublicKeyCredential $publicKeyCredential */
        $publicKeyCredential = $serializer->deserialize(
            file_get_contents('php://input'),
            PublicKeyCredential::class,
            'json'
        );

        if (!$publicKeyCredential->response instanceof AuthenticatorAssertionResponse) {
            $response->getBody()->write(json_encode(['verified' => false]));
            return $response;
        }

        $csmFactory = new CeremonyStepManagerFactory();

        if($this->container->get('site.debugMode')) {
            // https://webauthn-doc.spomky-labs.com/v5.2/pure-php/advanced-behaviours/dealing-with-localhost#enabling-http-localhost-for-development
            $csmFactory->setAllowedOrigins([
                'http://localhost:8080',
            ]);
        }

        $requestCSM = $csmFactory->requestCeremony();
        $authenticatorAssertionResponseValidator = AuthenticatorAssertionResponseValidator::create(
            $requestCSM
        );

        $publicKeyCredentialSource = $this->passkeyRepository->fetchCredentialSource($publicKeyCredential->rawId);

        $authenticatorAssertionResponseValidator->check(
            $publicKeyCredentialSource,
            $publicKeyCredential->response,
            PublicKeyCredentialRequestOptions::create($this->challenge->getToken()),
            $this->host,
            null
        );

        // TODO: Prüfen: ob user existiert!
        $this->session->setEntry(UserEntity::class, (int)$publicKeyCredentialSource->userHandle);
        $this->session->regenerateSession();

        $response->getBody()->write(json_encode(['verified' => true]));
        return $response;
    }

    /**
     * @throws InvalidArgumentException
     */
    private function getCredentialCreationOptions(UserEntity $user, ?string $challenge = null): PublicKeyCredentialCreationOptions
    {
        $rpEntity = PublicKeyCredentialRpEntity::create($this->appName, $this->host);

        $userEntity = PublicKeyCredentialUserEntity::create(
            $user->getMailAddr(),
            (string)$user->getUserId(),
            $user->getFullName()
        );

        $challenge = $challenge ?? $this->challenge->generateToken();

        return PublicKeyCredentialCreationOptions::create($rpEntity, $userEntity, $challenge);
    }

    private function serializeOptions(PublicKeyCredentialOptions $options): string
    {
        // The manager will receive data to load and select the appropriate
        $attestationStatementSupportManager = AttestationStatementSupportManager::create();
        $attestationStatementSupportManager->add(NoneAttestationStatementSupport::create());

        $factory = new WebauthnSerializerFactory($attestationStatementSupportManager);
        $serializer = $factory->create();

        // The serializer is the same as the one created in the previous pages
        return $serializer->serialize(
            $options,
            'json',
            [
                AbstractObjectNormalizer::SKIP_NULL_VALUES => true, // Highly recommended!
                JsonEncode::OPTIONS => JSON_THROW_ON_ERROR, // Optional
            ]
        );
    }

    /**
     * @throws DatabaseException
     * @throws Exception
     */
    private function getUser(): UserEntity
    {
        $userId = $this->session->getEntry(UserEntity::class);

        $user = $this->userRepository->loadUserById($userId);

        if (!$user->isAuthenticated()) {
            throw new HttpStatus403Forbidden('No user logged in');
        }
        return $user;
    }
}
