// Copyright 2021-present Etherna SA
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//     http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
            if (openIdConnectOptionsMonitor is null)
                throw new ArgumentNullException(nameof(openIdConnectOptionsMonitor));
            if (signInServiceOptions is null)
                throw new ArgumentNullException(nameof(signInServiceOptions));

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
