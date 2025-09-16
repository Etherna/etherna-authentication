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

using Duende.AccessTokenManagement.OpenIdConnect;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Etherna.Authentication.Native
{
    public class EthernaOpenIdConnectClient : EthernaOpenIdConnectClientBase
    {
        // Fields.
        private readonly IEthernaSignInService ethernaSignInService;
        private readonly IUserTokenManagementService userTokenManagementService;

        // Constructor.
        public EthernaOpenIdConnectClient(
            IDiscoveryDocumentService discoveryDocumentService,
            IEthernaSignInService ethernaSignInService,
            IUserTokenManagementService userTokenManagementService)
            : base(discoveryDocumentService)
        {
            this.ethernaSignInService = ethernaSignInService;
            this.userTokenManagementService = userTokenManagementService;
        }

        // Protected methods.
        protected override IEnumerable<Claim> GetCurrentUserClaims()
        {
            if (!ethernaSignInService.IsAuthenticated)
                throw new InvalidOperationException("User is not authenticated");

            return ethernaSignInService.CurrentUser!.Claims;
        }

        protected override async Task<string> GetUserAccessTokenAsync()
        {
            if (!ethernaSignInService.IsAuthenticated)
                throw new InvalidOperationException("User is not authenticated");

            var userToken = await userTokenManagementService.GetAccessTokenAsync(ethernaSignInService.CurrentUser!).ConfigureAwait(false);
            if (userToken.IsError)
                throw new InvalidOperationException($"Invalid token with error: {userToken.Error}");

            if (string.IsNullOrWhiteSpace(userToken.AccessToken))
                throw new InvalidOperationException("Invalid empty access token");

            return userToken.AccessToken;
        }

        protected override IEnumerable<Claim> TryGetCurrentUserClaims()
        {
            try
            {
                return GetCurrentUserClaims();
            }
            catch (InvalidOperationException)
            {
                return [];
            }
        }

        protected override async Task<string?> TryGetUserAccessTokenAsync()
        {
            try
            {
                return await GetUserAccessTokenAsync().ConfigureAwait(false);
            }
            catch (InvalidOperationException)
            {
                return null;
            }
        }
    }
}
