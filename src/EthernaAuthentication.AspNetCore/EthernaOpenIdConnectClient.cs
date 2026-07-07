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
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Etherna.Authentication.AspNetCore
{
    public class EthernaOpenIdConnectClient(
        IDiscoveryDocumentService discoveryDocumentService,
        IHttpContextAccessor httpContextAccessor)
        : EthernaOpenIdConnectClientBase(discoveryDocumentService)
    {
        // Protected methods.
        protected override IEnumerable<Claim> GetCurrentUserClaims()
        {
            var httpContext = httpContextAccessor.HttpContext ??
                throw new InvalidOperationException("HttpContext can't be null");

            return httpContext.User.Claims;
        }

        protected override async Task<string> GetUserAccessTokenAsync()
        {
            var httpContext = httpContextAccessor.HttpContext ??
                throw new InvalidOperationException("HttpContext can't be null");

            // Try with the managed user access token first, refreshed by token management when possible.
            // Token management can only refresh sessions carrying a refresh token, and logs an error
            // when the session carries no tokens at all, like with cookie sessions signed in without
            // an OpenId Connect handler: without a refresh token the raw session token is already the
            // best available, so skip the managed lookup.
            var refreshToken = await httpContext.GetTokenAsync("refresh_token").ConfigureAwait(false);
            if (!string.IsNullOrEmpty(refreshToken))
            {
                var managedToken = await httpContext.GetUserAccessTokenAsync().ConfigureAwait(false);
                if (managedToken.Succeeded && !string.IsNullOrWhiteSpace(managedToken.Token.AccessToken))
                    return managedToken.Token.AccessToken;
            }

            // Fall back on the raw token from the authentication session.
            // This is the case of requests authenticated with a plain bearer token, without a managed login session.
            return await httpContext.GetTokenAsync("access_token").ConfigureAwait(false) ??
                throw new InvalidOperationException("Invalid null access token");
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
