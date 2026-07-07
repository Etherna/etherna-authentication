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

using Etherna.Authentication.Native.CodeFlow;
using Etherna.Authentication.Native.PasswordFlow;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System;
using System.Net.Http;
using System.Threading.Tasks;
using Xunit;

namespace Etherna.Authentication.Native
{
    public sealed class ServiceCollectionExtensionsTest : IDisposable
    {
        // Consts.
        private const string Authority = "https://sso.example.com/";
        private const string ClientId = "testClientId";
        private const string HttpClientName = "testHttpClient";

        // Fields.
        private readonly ServiceProvider serviceProvider;

        // Constructor.
        public ServiceCollectionExtensionsTest()
        {
            var services = new ServiceCollection();
            services.AddEthernaOidcClient(
                Authority,
                ClientId,
                null,
                11420,
                [EthernaScopes.UserApiGateway],
                HttpClientName);
            serviceProvider = services.BuildServiceProvider();
        }

        // Dispose.
        public void Dispose() => serviceProvider.Dispose();

        // Tests.
        [Fact]
        public void ConfiguresApiKeyFlowOidcOptions()
        {
            var options = serviceProvider.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>()
                .Get(EthernaNativeDefaults.ApiKeyAuthenticationScheme);

            Assert.Equal(Authority, options.Authority);
            Assert.Equal(EthernaNativeDefaults.ApiKeyClientId, options.ClientId);
            Assert.True(options.SaveTokens);
            Assert.Contains("offline_access", options.Scope);
            Assert.Contains(EthernaScopes.EtherAccounts, options.Scope);
            Assert.Contains(EthernaScopes.UserApiGateway, options.Scope);
        }

        [Fact]
        public void ConfiguresCodeFlowOidcOptions()
        {
            var options = serviceProvider.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>()
                .Get(EthernaNativeDefaults.CodeAuthenticationScheme);

            Assert.Equal(Authority, options.Authority);
            Assert.Equal(ClientId, options.ClientId);
            Assert.Equal("code", options.ResponseType);
            Assert.True(options.SaveTokens);
            Assert.Contains("offline_access", options.Scope);
            Assert.Contains(EthernaScopes.EtherAccounts, options.Scope);
            Assert.Contains(EthernaScopes.UserApiGateway, options.Scope);
        }

        [Fact]
        public async Task RegistersBothAuthenticationSchemes()
        {
            var schemeProvider = serviceProvider.GetRequiredService<IAuthenticationSchemeProvider>();

            Assert.NotNull(await schemeProvider.GetSchemeAsync(EthernaNativeDefaults.ApiKeyAuthenticationScheme));
            Assert.NotNull(await schemeProvider.GetSchemeAsync(EthernaNativeDefaults.CodeAuthenticationScheme));
        }

        [Fact]
        public void RegistersManagedHttpClient()
        {
            using var httpClient = serviceProvider.GetRequiredService<IHttpClientFactory>()
                .CreateClient(HttpClientName);

            Assert.NotNull(httpClient);
        }

        [Fact]
        public void RegistersSignInServicesForBothFlows()
        {
            Assert.IsType<EthernaApiKeySignInService>(serviceProvider.GetRequiredService<IEthernaApiKeySignInService>());
            Assert.IsType<EthernaCodeSignInService>(serviceProvider.GetRequiredService<IEthernaCodeSignInService>());

            var signInService = serviceProvider.GetRequiredService<IEthernaSignInService>();
            Assert.IsType<EthernaSignInService>(signInService);
            Assert.False(signInService.IsAuthenticated);
        }

        [Fact]
        public void ResolvesOidcClientWithoutAuthentication()
        {
            var oidcClient = serviceProvider.GetRequiredService<IEthernaOpenIdConnectClient>();

            Assert.NotNull(oidcClient);
        }
    }
}
