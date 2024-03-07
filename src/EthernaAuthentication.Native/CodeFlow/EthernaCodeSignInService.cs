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
using IdentityModel.OidcClient;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using System;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Etherna.Authentication.Native.CodeFlow
{
    public class EthernaCodeSignInService : IEthernaSignInService
    {
        // Fields.
        private readonly OpenIdConnectOptions openIdConnectOptions;
        private readonly EthernaCodeSignInServiceOptions signInServiceOptions;
        private readonly IUserTokenStore userTokenStore;

        // Constructor.
        public EthernaCodeSignInService(
            IOptionsMonitor<OpenIdConnectOptions> openIdConnectOptionsMonitor,
            IOptions<EthernaCodeSignInServiceOptions> signInServiceOptions,
            IUserTokenStore userTokenStore)
        {
            ArgumentNullException.ThrowIfNull(openIdConnectOptionsMonitor, nameof(openIdConnectOptionsMonitor));
            ArgumentNullException.ThrowIfNull(signInServiceOptions, nameof(signInServiceOptions));

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
            // create a redirect URI using an available port on the loopback address.
            // requires the OP to allow random ports on 127.0.0.1 - otherwise set a static port
            var browser = new SystemBrowser(signInServiceOptions.ReturnUrlPort);
            var redirectUri = $"http://127.0.0.1:{browser.Port}";

            var options = new OidcClientOptions
            {
                Authority = openIdConnectOptions.Authority,
                ClientId = openIdConnectOptions.ClientId,
                RedirectUri = redirectUri,
                Scope = string.Join(' ', openIdConnectOptions.Scope),
                FilterClaims = false,

                Browser = browser,
                RefreshTokenInnerHttpHandler = new SocketsHttpHandler()
            };

            var oidcClient = new OidcClient(options);
            var loginResult = await oidcClient.LoginAsync(new LoginRequest()).ConfigureAwait(false);
            if (loginResult.IsError)
                throw new InvalidOperationException($"Error during authentication: {loginResult.Error}");

            // Store login result.
            CurrentUser = loginResult.User;
            await userTokenStore.StoreTokenAsync(
                loginResult.User,
                new UserToken
                {
                    AccessToken = loginResult.AccessToken,
                    Error = loginResult.Error,
                    Expiration = loginResult.AccessTokenExpiration,
                    RefreshToken = loginResult.RefreshToken,
                    Scope = options.Scope
                }).ConfigureAwait(false);
        }
    }
}
