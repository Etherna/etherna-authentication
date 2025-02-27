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

using IdentityModel.Client;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Text.Json;
using System.Threading.Tasks;

namespace Etherna.Authentication
{
    public abstract class EthernaOpenIdConnectClientBase(
        IDiscoveryDocumentService discoveryDocumentService)
        : IEthernaOpenIdConnectClient
    {
        // Fields.
        private IEnumerable<Claim>? userInfo;

        // Properties.
        public IDiscoveryDocumentService DiscoveryDocumentService { get; } = discoveryDocumentService;

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
            return JsonSerializer.Deserialize<string[]>(claim.Value) ?? [];
        }

        public async Task<string[]> GetRolesAsync()
        {
            var claim = await TryGetClaimAsync(EthernaClaimTypes.Role_Dotnet).ConfigureAwait(false) ??
                        await GetClaimAsync(EthernaClaimTypes.Role_IdentityModel).ConfigureAwait(false);
            return [claim.Value];
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

        public async Task<string[]?> TryGetRolesAsync()
        {
            var claim = await TryGetClaimAsync(EthernaClaimTypes.Role_Dotnet).ConfigureAwait(false) ??
                        await TryGetClaimAsync(EthernaClaimTypes.Role_IdentityModel).ConfigureAwait(false);
            return claim is null ? null : new[] { claim.Value };
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
        protected abstract IEnumerable<Claim> TryGetCurrentUserClaims();
        protected abstract Task<string?> TryGetUserAccessTokenAsync();

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
            var userClaims = TryGetCurrentUserClaims();
            var claim = userClaims.FirstOrDefault(c => c.Type == claimType);

            if (claim is not null)
                return claim;

            var accessToken = await TryGetUserAccessTokenAsync().ConfigureAwait(false);
            if (accessToken is null)
                return null;

            var userInfo = await GetUserInfoAsync(accessToken).ConfigureAwait(false);
            return userInfo.FirstOrDefault(c => c.Type == claimType);
        }
    }
}
