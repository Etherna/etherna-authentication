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
using Etherna.Authentication.Native.CodeFlow;
using Etherna.Authentication.Native.PasswordFlow;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace Etherna.Authentication.Native
{
    public sealed class EthernaSignInService(
        IEthernaApiKeySignInService apiKeySignInService,
        IEthernaCodeSignInService codeSignInService)
        : IEthernaSignInService, IUserAccessor
    {
        // Properties.
        public string? CurrentAuthenticationSchemeName { get; private set; }
        public ClaimsPrincipal? CurrentUser { get; private set; }
        public bool IsAuthenticated => CurrentUser is not null;

        // Methods.
        public Task<ClaimsPrincipal> GetCurrentUserAsync(CancellationToken ct = new()) =>
            Task.FromResult(CurrentUser ?? new ClaimsPrincipal());

        public async Task SignInAsync()
        {
            CurrentUser = await codeSignInService.SignInAsync().ConfigureAwait(false);
            CurrentAuthenticationSchemeName = codeSignInService.AuthenticationSchemeName;
        }

        public async Task SignInAsync(string apiKey)
        {
            CurrentUser = await apiKeySignInService.SignInAsync(apiKey).ConfigureAwait(false);
            CurrentAuthenticationSchemeName = apiKeySignInService.AuthenticationSchemeName;
        }
    }
}
