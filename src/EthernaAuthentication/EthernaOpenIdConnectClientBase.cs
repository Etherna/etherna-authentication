using IdentityModel.Client;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Text.Json;
using System.Threading.Tasks;

namespace Etherna.Authentication
{
    public abstract class EthernaOpenIdConnectClientBase : IEthernaOpenIdConnectClient
    {
        // Fields.
        private IEnumerable<Claim>? userInfo;

        // Constructor.
        protected EthernaOpenIdConnectClientBase(
            IDiscoveryDocumentService discoveryDocumentService)
        {
            DiscoveryDocumentService = discoveryDocumentService;
        }

        // Properties.
        public IDiscoveryDocumentService DiscoveryDocumentService { get; }

        // Methods.
        public async Task<string> GetClientIdAsync()
        {
            var claim = await GetClaimAsync(EthernaClaimTypes.ClientId).ConfigureAwait(false);
            return claim.Value;
        }

        public async Task<string> GetEtherAddressAsync()
        {
            var claim = await GetClaimAsync(EthernaClaimTypes.EtherAddress).ConfigureAwait(false);
            return claim.Value;
        }

        public async Task<string[]> GetEtherPrevAddressesAsync()
        {
            var claim = await GetClaimAsync(EthernaClaimTypes.EtherPreviousAddresses).ConfigureAwait(false);
            return JsonSerializer.Deserialize<string[]>(claim.Value) ?? Array.Empty<string>();
        }

        public async Task<string> GetUserIdAsync()
        {
            var claim = await GetClaimAsync(EthernaClaimTypes.UserId).ConfigureAwait(false);
            return claim.Value;
        }

        public async Task<string> GetUsernameAsync()
        {
            var claim = await GetClaimAsync(EthernaClaimTypes.Username).ConfigureAwait(false);
            return claim.Value;
        }

        public async Task<string?> TryGetClientIdAsync()
        {
            var claim = await TryGetClaimAsync(EthernaClaimTypes.ClientId).ConfigureAwait(false);
            return claim?.Value;
        }

        public async Task<string?> TryGetEtherAddressAsync()
        {
            var claim = await TryGetClaimAsync(EthernaClaimTypes.EtherAddress).ConfigureAwait(false);
            return claim?.Value;
        }

        public async Task<string[]?> TryGetEtherPrevAddressesAsync()
        {
            var claim = await TryGetClaimAsync(EthernaClaimTypes.EtherPreviousAddresses).ConfigureAwait(false);
            return claim is null ? null : JsonSerializer.Deserialize<string[]>(claim.Value);
        }

        public async Task<string?> TryGetUserIdAsync()
        {
            var claim = await TryGetClaimAsync(EthernaClaimTypes.UserId).ConfigureAwait(false);
            return claim?.Value;
        }

        public async Task<string?> TryGetUsernameAsync()
        {
            var claim = await TryGetClaimAsync(EthernaClaimTypes.Username).ConfigureAwait(false);
            return claim?.Value;
        }

        // Protected methods.
        protected abstract IEnumerable<Claim> GetCurrentUserClaims();
        protected abstract Task<string> GetUserAccessTokenAsync();

        // Helpers.
        private async Task<Claim> GetClaimAsync(string claimType)
        {
            var claim = await TryGetClaimAsync(claimType).ConfigureAwait(false);
            return claim ?? throw new KeyNotFoundException($"Claim type {claimType} not found");
        }

        private async Task<IEnumerable<Claim>> GetUserInfoAsync(string accessToken)
        {
            if (userInfo is null)
            {
                // Get discovery document.
                var discoveryDoc = await DiscoveryDocumentService.GetDiscoveryDocumentAsync().ConfigureAwait(false);

                // Get user info.
                using var httpClient = new HttpClient();
                using var userInfoRequest = new UserInfoRequest
                {
                    Address = discoveryDoc.UserInfoEndpoint,
                    Token = accessToken
                };
                var response = await httpClient.GetUserInfoAsync(userInfoRequest).ConfigureAwait(false);

                // Cache claims.
                userInfo = response.Claims;
            }

            return userInfo;
        }

        private async Task<Claim?> TryGetClaimAsync(string claimType)
        {
            var userClaims = GetCurrentUserClaims();
            var claim = userClaims.FirstOrDefault(c => c.Type == claimType);

            if (claim is not null)
                return claim;

            var accessToken = await GetUserAccessTokenAsync().ConfigureAwait(false);
            if (accessToken is null)
                return null;

            var userInfo = await GetUserInfoAsync(accessToken).ConfigureAwait(false);
            return userInfo.FirstOrDefault(c => c.Type == claimType);
        }
    }
}
