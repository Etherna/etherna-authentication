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
    }
}
