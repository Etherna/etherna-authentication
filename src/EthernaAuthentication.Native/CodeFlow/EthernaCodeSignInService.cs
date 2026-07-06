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
using Duende.AccessTokenManagement.OpenIdConnect;
using Duende.IdentityModel.OidcClient;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using System;
using System.Net.Http;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace Etherna.Authentication.Native.CodeFlow
{
    public class EthernaCodeSignInService : IEthernaSignInService, IUserAccessor
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
            ArgumentNullException.ThrowIfNull(openIdConnectOptionsMonitor);
            ArgumentNullException.ThrowIfNull(signInServiceOptions);

            openIdConnectOptions = openIdConnectOptionsMonitor.Get(
                signInServiceOptions.Value.AuthenticationSchemeName);
            this.signInServiceOptions = signInServiceOptions.Value;
            this.userTokenStore = userTokenStore;
        }

        // Properties.
        public ClaimsPrincipal? CurrentUser { get; private set; }
        public bool IsAuthenticated => CurrentUser != null;

        // Methods.
        public Task<ClaimsPrincipal> GetCurrentUserAsync(CancellationToken ct = new()) =>
            Task.FromResult(CurrentUser ?? new ClaimsPrincipal());
        
        public async Task SignInAsync()
        {
            // Create a redirect URI using an available port on the loopback address.
            // Requires the OP to allow random ports on 127.0.0.1 - otherwise set a static port.
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
            
            // Mute environment warnings in console opening browser.
            Environment.SetEnvironmentVariable("QT_LOGGING_RULES", "qt.qpa.*=false"); //QT warnings
            
            // Open browser.
            var loginResult = await oidcClient.LoginAsync(new LoginRequest()).ConfigureAwait(false);
            if (loginResult.IsError)
                throw new InvalidOperationException($"Error during authentication: {loginResult.Error}");

            // Store login result.
            CurrentUser = loginResult.User;
            await userTokenStore.StoreTokenAsync(
                loginResult.User,
                new UserToken
                {
                    ClientId = ClientId.Parse(openIdConnectOptions.ClientId!),
                    AccessTokenType = AccessTokenType.Parse("Bearer"),
                    AccessToken = AccessToken.Parse(loginResult.AccessToken),
                    Expiration = loginResult.AccessTokenExpiration,
                    RefreshToken = RefreshToken.Parse(loginResult.RefreshToken),
                    Scope = Scope.Parse(options.Scope)
                }).ConfigureAwait(false);
        }
    }
}
