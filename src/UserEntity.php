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

final class UserEntity
{
    public function __construct(
        protected ?int $userid = null,
        protected bool $isAdmin = false,
        protected string $firstName = '',
        protected string $lastName = '',
        protected string $mailAddr = ''
    ) {
    }

    public function isAuthenticated(): bool
    {
        return !is_null($this->userid);
    }

    public function getFirstName(): string
    {
        return $this->firstName;
    }

    public function getLastName(): string
    {
        return $this->lastName;
    }

    public function getUserName(): string
    {
        return "{$this->firstName[0]}. $this->lastName";
    }

    public function getFullName(): string
    {
        return trim("$this->firstName $this->lastName");
    }

    public function getMailAddr(): string
    {
        return $this->mailAddr;
    }

    public function getUserId(): ?int
    {
        return $this->userid;
    }

    public function isAdmin(): bool
    {
        return $this->isAdmin;
    }

    public function reset(): UserEntity
    {
        $this->firstName = '';
        $this->lastName = '';
        $this->mailAddr = '';
        $this->userid = null;
        $this->isAdmin = false;
        return $this;
    }
}
