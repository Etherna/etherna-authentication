//   Copyright 2021-present Etherna Sagl
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

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
