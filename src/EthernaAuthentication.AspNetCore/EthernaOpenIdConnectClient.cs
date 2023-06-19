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

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System;
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
        protected override ClaimsPrincipal GetCurrentUserClaimsPrincipal()
        {
            var httpContext = httpContextAccessor.HttpContext ??
                throw new InvalidOperationException("HttpContext can't be null");

            return httpContext.User;
        }

        protected override async Task<string> GetUserAccessTokenAsync()
        {
            var httpContext = httpContextAccessor.HttpContext ??
                throw new InvalidOperationException("HttpContext can't be null");

            return await httpContext.GetTokenAsync("access_token").ConfigureAwait(false) ??
                throw new InvalidOperationException("Invalid null access token");
        }
    }
}
