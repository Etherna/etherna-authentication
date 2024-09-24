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
using IdentityModel;
using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Etherna.Authentication.Native.PasswordFlow
{
    public class EthernaApiKeySignInService : IEthernaSignInService
    {
        // Fields.
        private readonly IOpenIdConnectConfigurationService openIdConnectConfigurationService;
        private readonly OpenIdConnectOptions openIdConnectOptions;
        private readonly EthernaApiKeySignInServiceOptions signInServiceOptions;
        private readonly IUserTokenStore userTokenStore;

        // Constructor.
        public EthernaApiKeySignInService(
            IOpenIdConnectConfigurationService openIdConnectConfigurationService,
            IOptionsMonitor<OpenIdConnectOptions> openIdConnectOptionsMonitor,
            IOptions<EthernaApiKeySignInServiceOptions> signInServiceOptions,
            IUserTokenStore userTokenStore)
        {
            ArgumentNullException.ThrowIfNull(openIdConnectOptionsMonitor, nameof(openIdConnectOptionsMonitor));
            ArgumentNullException.ThrowIfNull(signInServiceOptions, nameof(signInServiceOptions));

            this.openIdConnectConfigurationService = openIdConnectConfigurationService;
            openIdConnectOptions = openIdConnectOptionsMonitor.Get(
                signInServiceOptions.Value.AuthenticationSchemeName);
            this.signInServiceOptions = signInServiceOptions.Value;
            this.userTokenStore = userTokenStore;
        }

        // Properties.
        public ClaimsPrincipal? CurrentUser { get; private set; }
        public bool IsAuthenticated => CurrentUser != null;

        // Methods.
        public async Task SignInAsync()
        {
            // Check conditions.
            if (string.IsNullOrWhiteSpace(signInServiceOptions.ApiKey))
                throw new InvalidOperationException("Invalid empty api key");

            // Split api key.
            var splitApiKey = signInServiceOptions.ApiKey.Split('.');
            if (splitApiKey.Length != 2)
                throw new InvalidOperationException("Invalid api key");

            // Get oidc config.
            var oidcConfig = await openIdConnectConfigurationService.GetOpenIdConnectConfigurationAsync(
                signInServiceOptions.AuthenticationSchemeName).ConfigureAwait(false);

            // Perform authentication request.
            using var client = new HttpClient();
            using var request = new PasswordTokenRequest
            {
                Address = oidcConfig.TokenEndpoint,

                ClientId = oidcConfig.ClientId!,
                Scope = string.Join(' ', openIdConnectOptions.Scope),

                UserName = splitApiKey[0],
                Password = splitApiKey[1]
            };

            var tokenResponse = await client.RequestPasswordTokenAsync(request).ConfigureAwait(false);
            if (tokenResponse.IsError)
                throw new InvalidOperationException($"Error during authentication: {tokenResponse.Error}");

            // Decode access token.
            var token = new JwtSecurityTokenHandler().ReadJwtToken(tokenResponse.AccessToken);

            // Store login result.
            CurrentUser = Principal.Create(oidcConfig.Authority!, token.Claims.ToArray());
            await userTokenStore.StoreTokenAsync(
                CurrentUser,
                new UserToken
                {
                    AccessToken = tokenResponse.AccessToken,
                    AccessTokenType = tokenResponse.TokenType,
                    Error = tokenResponse.Error,
                    Expiration = DateTimeOffset.Now.AddSeconds(tokenResponse.ExpiresIn),
                    RefreshToken = tokenResponse.RefreshToken,
                    Scope = tokenResponse.Scope
                }).ConfigureAwait(false);
        }
    }
}
