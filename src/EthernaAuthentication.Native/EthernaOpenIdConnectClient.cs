// Copyright 2021-present Etherna SA
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//     http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
                return Array.Empty<Claim>();
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
