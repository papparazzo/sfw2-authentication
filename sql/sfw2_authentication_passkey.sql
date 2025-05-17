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

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET time_zone = "+00:00";

CREATE TABLE IF NOT EXISTS `{TABLE_PREFIX}_authentication_passkey` (
    `Id` INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
    `UserId` INT(11) UNSIGNED NOT NULL,
    `PublicKeyCredentialId` VARBINARY(255) NOT NULL,
    `Type` VARCHAR(32) NOT NULL,
    `Transports` JSON NOT NULL,
    `AttestationType` VARCHAR(32) NOT NULL,
    `TrustPath` JSON NOT NULL,
    `Aaguid` CHAR(36) NOT NULL,
    `CredentialPublicKey` VARBINARY(255) NOT NULL,
    `Counter` INT UNSIGNED NOT NULL DEFAULT 0,
    `CreatedAt` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `UpdatedAt` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`Id`),
    UNIQUE KEY `idx_credential_id` (`PublicKeyCredentialId`),
    KEY `idx_user_handle` (`UserId`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

