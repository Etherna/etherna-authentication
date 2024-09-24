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

using Duende.AccessTokenManagement;
using Duende.AccessTokenManagement.OpenIdConnect;
using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace Etherna.Authentication.Native
{
    public class LocalUserAccessTokenHandler : AccessTokenHandler
    {
        private readonly UserTokenRequestParameters parameters;
        private readonly IEthernaSignInService ethernaSignInService;
        private readonly IUserTokenManagementService userTokenManagementService;

        public LocalUserAccessTokenHandler(
            IDPoPProofService dPoPProofService,
            IDPoPNonceStore dPoPNonceStore,
            IEthernaSignInService ethernaSignInService,
            ILogger<LocalUserAccessTokenHandler> logger,
            IUserTokenManagementService userTokenManagementService,
            UserTokenRequestParameters? parameters = null)
            : base(dPoPProofService, dPoPNonceStore, logger)
        {
            this.ethernaSignInService = ethernaSignInService;
            this.userTokenManagementService = userTokenManagementService;
            this.parameters = parameters ?? new UserTokenRequestParameters();
        }

        protected override async Task<ClientCredentialsToken> GetAccessTokenAsync(
            bool forceRenewal,
            CancellationToken cancellationToken)
        {
            if (!ethernaSignInService.IsAuthenticated)
                throw new InvalidOperationException("User is not authenticated");

            return await userTokenManagementService.GetAccessTokenAsync(
                ethernaSignInService.CurrentUser!,
                new UserTokenRequestParameters
                {
                    SignInScheme = parameters.SignInScheme,
                    ChallengeScheme = parameters.ChallengeScheme,
                    Resource = parameters.Resource,
                    Context = parameters.Context,
                    ForceRenewal = forceRenewal,
                },
                cancellationToken).ConfigureAwait(false);
        }
    }
}
