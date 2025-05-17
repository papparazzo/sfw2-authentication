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

namespace SFW2\Authentication;

use SFW2\Database\DatabaseInterface;
use SFW2\Database\QueryHelper;
use SFW2\Exception\HttpExceptions\Status4xx\HttpStatus400BadRequest;
use Symfony\Component\Uid\Uuid;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\TrustPath\EmptyTrustPath;
use Webauthn\TrustPath\TrustPath;

class PasskeyRepository
{
    public function __construct(
        protected readonly DatabaseInterface $database
    ) {
    }

    public function saveCredentialSource(PublicKeyCredentialSource $publicKeyCredentialSource): void
    {
        $this->database->insert("
            INSERT INTO `{TABLE_PREFIX}_authentication_passkey` (
                `PublicKeyCredentialId`,
                `Type` ,
                `Transports`,
                `AttestationType`,
                `TrustPath`,
                `Aaguid`,
                `CredentialPublicKey`,
                `UserId`,
                `Counter`
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
            [
                $publicKeyCredentialSource->publicKeyCredentialId,
                $publicKeyCredentialSource->type,
                json_encode($publicKeyCredentialSource->transports),
                $publicKeyCredentialSource->attestationType,
                json_encode($publicKeyCredentialSource->trustPath),
                $publicKeyCredentialSource->aaguid,
                $publicKeyCredentialSource->credentialPublicKey,
                (int)$publicKeyCredentialSource->userHandle,
                $publicKeyCredentialSource->counter
            ]
        );
    }

    public function fetchCredentialSource(string $rawId): PublicKeyCredentialSource
    {
        $helper = new QueryHelper($this->database);
        $rs = $helper->selectRow(
            "SELECT * FROM `{TABLE_PREFIX}_authentication_passkey` WHERE `PublicKeyCredentialId` = %s",
            [$rawId],
        );

        if ($rs === null) {
            throw new HttpStatus400BadRequest("no credential found for id");
        }

        return PublicKeyCredentialSource::create(
            $rs['PublicKeyCredentialId'],
            $rs['Type'],
            json_decode($rs['Transports']),
            $rs['AttestationType'],
            EmptyTrustPath::create(),
            Uuid::fromString($rs['Aaguid']),
            $rs['CredentialPublicKey'],
            (string)$rs['UserId'],
            $rs['Counter']
        );
    }
}