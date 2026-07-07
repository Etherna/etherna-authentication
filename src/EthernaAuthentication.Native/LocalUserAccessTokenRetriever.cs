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

using Duende.AccessTokenManagement;
using Duende.AccessTokenManagement.DPoP;
using Duende.AccessTokenManagement.OpenIdConnect;
using System.Net.Http;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace Etherna.Authentication.Native
{
    public class LocalUserAccessTokenRetriever(
        IEthernaSignInService ethernaSignInService,
        IUserTokenManager userTokenManager,
        UserTokenRequestParameters? parameters = null)
        : AccessTokenRequestHandler.ITokenRetriever
    {
        private readonly UserTokenRequestParameters parameters = parameters ?? new UserTokenRequestParameters();

        public async Task<TokenResult<AccessTokenRequestHandler.IToken>> GetTokenAsync(
            HttpRequestMessage request,
            CancellationToken ct)
        {
            //refresh must run on the scheme of the flow used to sign in: client ids differ between flows
            var challengeScheme = parameters.ChallengeScheme;
            if (challengeScheme is null && ethernaSignInService.CurrentAuthenticationSchemeName is not null)
                challengeScheme = Scheme.Parse(ethernaSignInService.CurrentAuthenticationSchemeName);

            var tokenResult = await userTokenManager.GetAccessTokenAsync(
                ethernaSignInService.CurrentUser ?? new ClaimsPrincipal(),
                new UserTokenRequestParameters
                {
                    SignInScheme = parameters.SignInScheme,
                    ChallengeScheme = challengeScheme,
                    Resource = parameters.Resource,
                    Context = parameters.Context,
                    ForceTokenRenewal = request.GetForceRenewal(),
                },
                ct).ConfigureAwait(false);

            return tokenResult.Succeeded
                ? TokenResult.Success<AccessTokenRequestHandler.IToken>(tokenResult.Token)
                : tokenResult.FailedResult;
        }
    }
}
