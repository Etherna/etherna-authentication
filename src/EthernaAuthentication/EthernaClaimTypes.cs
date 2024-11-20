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

using IdentityModel;
using System.Security.Claims;

namespace Etherna.Authentication
{
    public static class EthernaClaimTypes
    {
        public const string ClientId = "client_id";
        public const string EtherAddress = "ether_address";
        public const string EtherPreviousAddresses = "ether_prev_addresses";
        public const string IsWeb3Account = "isWeb3Account";
#pragma warning disable CA1707
        public const string Role_Dotnet = ClaimTypes.Role;
        public const string Role_IdentityModel = JwtClaimTypes.Role;
#pragma warning restore CA1707
        public const string UserId = JwtClaimTypes.Subject;
        public const string Username = "preferred_username";
    }
}
