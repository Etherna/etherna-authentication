// Copyright 2021-present Etherna SA
// This file is part of EthernaAuthentication.
// 
// EthernaAuthentication is free software: you can redistribute it and/or modify it under the terms of the
// GNU Lesser General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
// 
// EthernaAuthentication is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License along with EthernaAuthentication.
// If not, see <https://www.gnu.org/licenses/>.

namespace Etherna.Authentication
{
    public static class EthernaScopes
    {
        // Standard OIDC identity scopes.
        public const string OpenId = "openid";
        public const string Profile = "profile";

        // Custom identity scopes.
        public const string EtherAccounts = "ether_accounts";
        public const string Role = "role";

        // User-facing API scopes (accessible to developer clients).
        public const string UserApiCredit = "userApi.credit";
        public const string UserApiGateway = "userApi.gateway";
        public const string UserApiIndex = "userApi.index";
        public const string UserApiSso = "userApi.sso";

        // Service-to-service interaction scopes (admin-created clients only).
        public const string EthernaCreditServiceInteract = "ethernaCredit_serviceInteract_api";
        public const string EthernaSsoUserContactInfo = "ethernaSso_userContactInfo_api";
    }
}