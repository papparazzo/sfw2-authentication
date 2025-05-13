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

use SFW2\Database\DatabaseException;
use SFW2\Database\DatabaseInterface;
use SFW2\Database\QueryHelper;
use SFW2\Validator\Exception;

class UserRepository
{
    public function __construct(
        protected readonly DatabaseInterface $database
    ) {
    }

    /**
     * @throws Exception
     * @throws DatabaseException
     */
    public function loadUserById(?int $userId): UserEntity
    {
        if (is_null($userId)) {
            return new UserEntity();
        }

        $stmt = /** @lang MySQL */
            "SELECT `Id`, `FirstName`, `LastName`, `Email`, `Password`, `Admin` " .
            "FROM `{TABLE_PREFIX}_authority_user` " .
            "WHERE `Id` = %s " .
            "AND `Active` = '1'";

        $queryHelper = new QueryHelper($this->database);
        $rv = $queryHelper->selectRow($stmt, [$userId]);

        if (empty($rv)) {
            throw new Exception("no user found with id <$userId>");
        }
        return $this->fill($rv);
    }

    /**
     * @throws Exception
     * @throws DatabaseException
     */
    public function loadUserByEmailAddress(string $userName): UserEntity
    {
        $stmt = /** @lang MySQL */
            "SELECT `Id`, `FirstName`, `LastName`, `Email`, `Password`, `Admin` " .
            "FROM `{TABLE_PREFIX}_authority_user` " .
            "WHERE `Email` = %s";

        $queryHelper = new QueryHelper($this->database);
        $row = $queryHelper->selectRow($stmt, [$userName]);

        if (empty($row)) {
            throw new Exception("no user found with login <$userName>");
        }
        return $this->fill($row);
    }

    public function fill(array $rv): UserEntity
    {
        return new UserEntity(
            $rv['Id'],
    $rv['Admin'] == '1',
            $rv['FirstName'],
            $rv['LastName'],
            $rv['Email'],
        );
    }

    /**
     * `Active` BOOLEAN NOT NULL DEFAULT '1',
     * `FirstName` VARCHAR(50) COLLATE utf8_unicode_ci NOT NULL,
     * `LastName` VARCHAR(50) COLLATE utf8_unicode_ci NOT NULL,
     * `Sex` ENUM('FEMALE','MALE','DIVERSE') COLLATE utf8_unicode_ci DEFAULT NULL,
     * `Birthday` DATE DEFAULT NULL,
     * `Email` VARCHAR(50) COLLATE utf8_unicode_ci NOT NULL,
     * `Phone` VARCHAR(25) COLLATE utf8_unicode_ci NOT NULL,
     *` Street` VARCHAR(50) COLLATE utf8_unicode_ci NOT NULL,
     * `HouseNumber` VARCHAR(25) COLLATE utf8_unicode_ci NOT NULL,
     * `PostalCode` VARCHAR(25) COLLATE utf8_unicode_ci NOT NULL,
     * `City` VARCHAR(25) COLLATE utf8_unicode_ci NOT NULL,
     *
     * Straße
     * Hausnummer
     * Plz
     * Ort
     *
     */

}