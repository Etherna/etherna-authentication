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
