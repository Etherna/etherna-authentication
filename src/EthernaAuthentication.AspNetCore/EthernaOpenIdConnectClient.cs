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

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Etherna.Authentication.AspNetCore
{
    public class EthernaOpenIdConnectClient : EthernaOpenIdConnectClientBase
    {
        // Fields.
        private readonly IHttpContextAccessor httpContextAccessor;

        // Constructor.
        public EthernaOpenIdConnectClient(
            IDiscoveryDocumentService discoveryDocumentService,
            IHttpContextAccessor httpContextAccessor)
            : base(discoveryDocumentService)
        {
            this.httpContextAccessor = httpContextAccessor;
        }

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
