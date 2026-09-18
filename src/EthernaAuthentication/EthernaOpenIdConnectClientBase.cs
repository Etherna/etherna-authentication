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

using Duende.IdentityModel.Client;
using Etherna.Authentication.Extensions;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Etherna.Authentication
{
    public abstract class EthernaOpenIdConnectClientBase(
        IDiscoveryDocumentService discoveryDocumentService,
        ILogger logger)
        : IEthernaOpenIdConnectClient
    {
        // Internal classes.
        //immutable, so a client shared by concurrent callers replaces its cached outcome in one step
        private sealed record UserInfoOutcome(
            string AccessToken,
            IEnumerable<Claim> Claims,
            long? ExpirationTickCount,
            bool IsUserTokenRejected);

        // Fields.
        //shared client: avoids per-call socket allocation. Recycling pooled connections keeps
        //DNS changes visible despite the client living for the whole process. Round-trips
        //are bounded per request by UserInfoTimeout, instead of the client own timeout.
        private static readonly HttpClient userInfoHttpClient = new(
            new SocketsHttpHandler { PooledConnectionLifetime = TimeSpan.FromMinutes(5) })
        {
            Timeout = Timeout.InfiniteTimeSpan
        };
        private UserInfoOutcome? userInfoOutcome;

        // Properties.
        public IDiscoveryDocumentService DiscoveryDocumentService { get; } = discoveryDocumentService;

        // Internal properties.
        internal virtual TimeSpan UserInfoFailureRetryDelay => TimeSpan.FromMinutes(1);

        //well below the 100s HttpClient default timeout
        internal virtual TimeSpan UserInfoTimeout => TimeSpan.FromSeconds(15);

        // Methods.
        public async Task<string> GetClientIdAsync()
        {
            var claim = (await GetClaimAsync(EthernaClaimTypes.ClientId).ConfigureAwait(false)).First();
            return claim.Value;
        }

        public async Task<string> GetEtherAddressAsync()
        {
            var claim = (await GetClaimAsync(EthernaClaimTypes.EtherAddress).ConfigureAwait(false)).First();
            return claim.Value;
        }

        public async Task<string[]> GetEtherPrevAddressesAsync()
        {
            var claim = (await GetClaimAsync(EthernaClaimTypes.EtherPreviousAddresses).ConfigureAwait(false)).First();
            return JsonSerializer.Deserialize(claim.Value, ClaimJsonSerializerContext.Default.StringArray) ?? [];
        }

        public async Task<string[]> GetRolesAsync()
        {
            var claims = await TryGetClaimAsync(EthernaClaimTypes.Role_Dotnet).ConfigureAwait(false);
            if (claims.Length == 0)
                claims = await GetClaimAsync(EthernaClaimTypes.Role_IdentityModel).ConfigureAwait(false);

            return claims.Select(c => c.Value).ToArray();
        }

        public async Task<string> GetUserIdAsync()
        {
            var claim = (await GetClaimAsync(EthernaClaimTypes.UserId).ConfigureAwait(false)).First();
            return claim.Value;
        }

        public async Task<string> GetUsernameAsync()
        {
            var claim = (await GetClaimAsync(EthernaClaimTypes.Username).ConfigureAwait(false)).First();
            return claim.Value;
        }

        public async Task<bool> HasScopesAsync(params string[] scopes)
        {
            var claims = await TryGetClaimAsync(EthernaClaimTypes.Scope).ConfigureAwait(false);
            return new HashSet<string>(claims.Select(c => c.Value)).IsSupersetOf(scopes);
        }

        public async Task<bool> IsUserTokenRejectedAsync()
        {
            var userInfo = await TryGetUserInfoAsync().ConfigureAwait(false);
            return userInfo?.IsUserTokenRejected ?? false;
        }

        public async Task<string?> TryGetClientIdAsync()
        {
            var claim = (await TryGetClaimAsync(EthernaClaimTypes.ClientId).ConfigureAwait(false)).FirstOrDefault();
            return claim?.Value;
        }

        public async Task<string?> TryGetEtherAddressAsync()
        {
            var claim = (await TryGetClaimAsync(EthernaClaimTypes.EtherAddress).ConfigureAwait(false)).FirstOrDefault();
            return claim?.Value;
        }

        public async Task<string[]?> TryGetEtherPrevAddressesAsync()
        {
            var claim = (await TryGetClaimAsync(EthernaClaimTypes.EtherPreviousAddresses).ConfigureAwait(false)).FirstOrDefault();
            return claim is null ? null : JsonSerializer.Deserialize(claim.Value, ClaimJsonSerializerContext.Default.StringArray);
        }

        public async Task<string[]?> TryGetRolesAsync()
        {
            var claims = await TryGetClaimAsync(EthernaClaimTypes.Role_Dotnet).ConfigureAwait(false);
            if (claims.Length == 0)
                claims = await TryGetClaimAsync(EthernaClaimTypes.Role_IdentityModel).ConfigureAwait(false);

            if (claims.Length == 0)
                return null;
            return claims.Select(c => c.Value).ToArray();
        }

        public async Task<string?> TryGetUserIdAsync()
        {
            var claim = (await TryGetClaimAsync(EthernaClaimTypes.UserId).ConfigureAwait(false)).FirstOrDefault();
            return claim?.Value;
        }

        public async Task<string?> TryGetUsernameAsync()
        {
            var claim = (await TryGetClaimAsync(EthernaClaimTypes.Username).ConfigureAwait(false)).FirstOrDefault();
            return claim?.Value;
        }

        // Protected methods.
        protected abstract IEnumerable<Claim> GetCurrentUserClaims();
        protected abstract Task<string> GetUserAccessTokenAsync();
        protected abstract IEnumerable<Claim> TryGetCurrentUserClaims();
        protected abstract Task<string?> TryGetUserAccessTokenAsync();

        // Helpers.
        private async Task<Claim[]> GetClaimAsync(string claimType)
        {
            var claims = await TryGetClaimAsync(claimType).ConfigureAwait(false);
            if (claims.Length == 0)
                throw new KeyNotFoundException($"Claim type {claimType} not found");
            return claims;
        }

        private async Task<Claim[]> TryGetClaimAsync(string claimType)
        {
            var claims = TryGetCurrentUserClaims().Where(c => c.Type == claimType).ToArray();
            if (claims.Length != 0)
                return claims;

            var userInfo = await TryGetUserInfoAsync().ConfigureAwait(false);
            return userInfo?.Claims.Where(c => c.Type == claimType).ToArray() ?? [];
        }

        private async Task<UserInfoOutcome?> TryGetUserInfoAsync()
        {
            // Machine principals (e.g. from client credentials tokens) have no subject claim, and the
            // userinfo endpoint requires one: all their claims already live in the token, don't search further.
            // The subject can appear as "sub" or mapped to the .NET name identifier, depending on the handler.
            if (!TryGetCurrentUserClaims().Any(c => c.Type is EthernaClaimTypes.UserId or ClaimTypes.NameIdentifier))
                return null;

            var accessToken = await TryGetUserAccessTokenAsync().ConfigureAwait(false);
            if (accessToken is null)
                return null;

            // A cached outcome holds only for the access token it was obtained with: a client can outlive
            // it (e.g. registered as singleton), through token refreshes, sign outs and new sign ins.
            var cachedOutcome = userInfoOutcome;
            if (cachedOutcome?.AccessToken == accessToken &&
                (cachedOutcome.ExpirationTickCount is null || Environment.TickCount64 < cachedOutcome.ExpirationTickCount))
                return cachedOutcome;

            // Get discovery document.
            var discoveryDoc = await DiscoveryDocumentService.GetDiscoveryDocumentAsync().ConfigureAwait(false);

            // Get user info.
            using var userInfoRequest = new UserInfoRequest
            {
                Address = discoveryDoc.UserInfoEndpoint,
                Token = accessToken
            };
            using var timeoutSource = new CancellationTokenSource(UserInfoTimeout);
            UserInfoResponse response;
            try
            {
                response = await userInfoHttpClient.GetUserInfoAsync(userInfoRequest, timeoutSource.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException e)
            {
                //the timeout is the only failure not answered as an error response
                response = ProtocolResponse.FromException<UserInfoResponse>(e);
            }

            if (response.IsError)
                logger.UserInfoRequestFailed(response.ErrorType, response.Error, response.Exception);

            // Cache the outcome. An error response carries no claims, and a failed request not even
            // the empty set: cache any error as no claims, so the endpoint isn't asked at every claim.
            // A failed request and a server error tell nothing about the token, and may not happen again:
            // they expire, while any other outcome holds as long as the token.
            var isTransientFailure = response.ErrorType is ResponseErrorType.Exception ||
                                     response.HttpStatusCode >= HttpStatusCode.InternalServerError;
            return userInfoOutcome = new UserInfoOutcome(
                accessToken,
                response.IsError ? [] : response.Claims,
                isTransientFailure ? Environment.TickCount64 + (long)UserInfoFailureRetryDelay.TotalMilliseconds : null,
                response.HttpStatusCode == HttpStatusCode.Unauthorized);
        }
    }
}
