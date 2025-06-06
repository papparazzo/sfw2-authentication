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

namespace SFW2\Authentication\Controller;

use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use SFW2\Authentication\Authenticator;
use SFW2\Interoperability\User\UserEntity;
use SFW2\Interoperability\User\UserRepositoryInterface;
use SFW2\Database\DatabaseException;
use SFW2\Database\DatabaseInterface;
use SFW2\Render\RenderInterface;
use SFW2\Session\SessionInterface;
use SFW2\Validator\Exception;

final class Authentication
{
    public function __construct(
        private readonly SessionInterface        $session,
        private readonly DatabaseInterface       $database,
        private readonly RenderInterface         $render,
        private readonly UserRepositoryInterface $userRepository,
        protected ?string                        $loginResetPath = null
    ) {
    }

    /**
     * @throws Exception
     * @throws DatabaseException
     */
    public function getLogin(Request $request, Response $response, array $args): Response
    {
        $userId = $this->session->getEntry(UserEntity::class);

        $user = $this->userRepository->loadUserById($userId);

        if (!$user->isAuthenticated()) {
            return $this->render->render($request, $response, [], 'SFW2\\Authentication\\Authentication\\LoginForm');
        }

        $data = [
            'user_name' => $user->getFullName()
        ];
        return $this->render->render($request, $response, $data, 'SFW2\\Authentication\\Authentication\\LogoutForm');
    }

    /**
     * @throws DatabaseException
     */
    public function postLogin(Request $request, Response $response, array $args): Response
    {
        $auth = new Authenticator($this->database);
        $user = $auth->authenticateUser(
            (string)filter_input(INPUT_POST, 'usr'),
            (string)filter_input(INPUT_POST, 'pwd')
        );

        if (!$user->isAuthenticated()) {
            $values['pwd']['hint'] = 'Es wurden ungültige Daten übermittelt!';
            $values['usr']['hint'] = ' ';
            $response = $this->render->render($request, $response, ['sfw2_payload' => $values]);
            return $response->withStatus(StatusCodeInterface::STATUS_UNPROCESSABLE_ENTITY);
        }

        $this->session->setEntry(UserEntity::class, $user->getUserId());
        $this->session->regenerateSession();

        $data = [];
        $data['user_name'] = $user->getFirstName();
        $data['user_id'] = $user->getUserId();
        $data['authenticated'] = $user->isAuthenticated();

        $request = $request->withAttribute('sfw2_authority', $data);

        $data = ['reload' => true];

        if (isset($request->getQueryParams()['showHint'])) {
            $data['title'] = 'Anmelden';
            $data['description'] = "
                Hallo <strong>{$user->getFirstName()}</strong>,<br />
                du wurdest erfolgreich angemeldet. 
                Zum Abmelden klicke bitte oben rechts auf <strong>abmelden</strong>
            ";
        }
        return $this->render->render($request, $response, $data);
    }

    public function postLogout(Request $request, Response $response, array $args): Response
    {
        $this->session->deleteEntry(UserEntity::class);
        $this->session->regenerateSession();

        $data = ['reload' => true];

        if (isset($request->getQueryParams()['showHint'])) {
            $data['title'] = 'Abmelden';
            $data['description'] =
                'Du wurdest erfolgreich abgemeldet. ' .
                'Um dich erneut anzumelden klicke bitte oben rechts auf Login.';
        }
        return $this->render->render($request, $response, $data);
    }
}
