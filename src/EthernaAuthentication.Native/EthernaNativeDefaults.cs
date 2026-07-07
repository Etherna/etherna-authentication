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

namespace Etherna.Authentication.Native
{
    /// <summary>
    /// Default values for the Etherna native authentication flows.
    /// </summary>
    public static class EthernaNativeDefaults
    {
        /// <summary>
        /// The authentication scheme for the api key (password) flow. The value is <c>EthernaApiKey</c>.
        /// </summary>
        public const string ApiKeyAuthenticationScheme = "EthernaApiKey";

        /// <summary>
        /// The OpenID Connect client id dedicated to api key sign-in, registered on the Etherna SSO server.
        /// </summary>
        public const string ApiKeyClientId = "apiKeyClientId";

        /// <summary>
        /// The display name for the api key authentication scheme.
        /// </summary>
        public const string ApiKeyDisplayName = "Etherna api key";

        /// <summary>
        /// The authentication scheme for the interactive code flow.
        /// Same value as <see cref="EthernaDefaults.AuthenticationScheme"/>.
        /// </summary>
        public const string CodeAuthenticationScheme = EthernaDefaults.AuthenticationScheme;

        /// <summary>
        /// The display name for the code flow authentication scheme.
        /// </summary>
        public const string CodeDisplayName = EthernaDefaults.DisplayName;
    }
}
