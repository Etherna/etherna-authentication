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
using Etherna.Authentication.Native.CodeFlow;
using Etherna.Authentication.Native.PasswordFlow;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;

namespace Etherna.Authentication.Native
{
    public static class ServiceCollectionExtensions
    {
        /// <summary>
        /// Register the Etherna OpenID Connect client with all the native sign-in flows: interactive
        /// code flow and api key (password) flow. The flow to use is selected at sign-in time, choosing
        /// the <see cref="IEthernaSignInService"/>.<c>SignInAsync</c> overload and eventually passing an
        /// api key, without any registration-time commitment.
        /// </summary>
        /// <param name="services">The service collection</param>
        /// <param name="authority">The Etherna SSO server url</param>
        /// <param name="clientId">The OpenID Connect client id used by the code flow</param>
        /// <param name="clientSecret">The optional client secret used by the code flow</param>
        /// <param name="returnUrlPort">The local loopback port receiving the code flow redirect</param>
        /// <param name="scopes">The api scopes to request, in addition to the always requested
        /// <c>offline_access</c> and <c>ether_accounts</c></param>
        /// <param name="managedHttpClientName">The optional name of a managed <see cref="HttpClient"/>
        /// attaching the user access token to every request</param>
        /// <param name="configureManagedHttpClient">An optional configuration of the managed http client</param>
        public static void AddEthernaOidcClient(
            this IServiceCollection services,
            string authority,
            string clientId,
            string? clientSecret,
            int returnUrlPort,
            IEnumerable<string> scopes,
            string? managedHttpClientName = null,
            Action<HttpClient>? configureManagedHttpClient = null)
        {
            // Check conditions.
            ArgumentNullException.ThrowIfNull(services);
            ArgumentNullException.ThrowIfNull(authority);
            ArgumentNullException.ThrowIfNull(clientId);
            ArgumentNullException.ThrowIfNull(scopes);

            var scopesArray = scopes.ToArray();
            void ConfigureCommonOidcOptions(OpenIdConnectOptions options)
            {
                options.Authority = authority;
                options.SaveTokens = true;
                options.Scope.Add("offline_access");
                options.Scope.Add(EthernaScopes.EtherAccounts);
                foreach (var scope in scopesArray)
                    options.Scope.Add(scope);
            }

            // Register cache to keep tokens.
            services.AddHybridCache();
            services.AddSingleton<IUserTokenStore, LocalUserTokenStore>();

            // Add Etherna OpenID Connect.
            services.AddSingleton<IDiscoveryDocumentService>(new DiscoveryDocumentService(authority));
            services.AddSingleton<IEthernaOpenIdConnectClient, EthernaOpenIdConnectClient>();

            // One scheme per sign in flow: the api key flow uses a dedicated client on the SSO server.
            // With more than one scheme a default challenge scheme is required by token management,
            // but sign in and token refresh always pass the scheme of the flow in use explicitly.
            services.AddAuthentication(options =>
                    options.DefaultChallengeScheme = EthernaNativeDefaults.CodeAuthenticationScheme)
                .AddOpenIdConnect(
                    EthernaNativeDefaults.CodeAuthenticationScheme,
                    EthernaNativeDefaults.CodeDisplayName,
                    options =>
                    {
                        ConfigureCommonOidcOptions(options);
                        options.ClientId = clientId;
                        options.ClientSecret = clientSecret;
                        options.ResponseType = "code";
                    })
                .AddOpenIdConnect(
                    EthernaNativeDefaults.ApiKeyAuthenticationScheme,
                    EthernaNativeDefaults.ApiKeyDisplayName,
                    options =>
                    {
                        ConfigureCommonOidcOptions(options);
                        options.ClientId = EthernaNativeDefaults.ApiKeyClientId;
                    });

            // Adds services for token management.
            services.AddOpenIdConnectAccessTokenManagement();

            // Add Etherna sign in services, one per flow, plus the flow selector facade.
            services.Configure<EthernaCodeSignInServiceOptions>(options =>
            {
                options.ReturnUrlPort = returnUrlPort;
            });
            services.AddSingleton<IEthernaApiKeySignInService, EthernaApiKeySignInService>();
            services.AddSingleton<IEthernaCodeSignInService, EthernaCodeSignInService>();
            services.AddSingleton<IEthernaSignInService, EthernaSignInService>();
            services.AddSingleton<IUserAccessor>(provider =>
                (EthernaSignInService)provider.GetRequiredService<IEthernaSignInService>());

            // Register HTTP client that uses the managed user access token.
            if (managedHttpClientName is not null)
            {
                var httpClientBuilder = configureManagedHttpClient is null ?
                    services.AddHttpClient(managedHttpClientName) :
                    services.AddHttpClient(managedHttpClientName, configureManagedHttpClient);

                services.AddTransient<LocalUserAccessTokenRetriever>();
                httpClientBuilder.AddHttpMessageHandler(provider => new AccessTokenRequestHandler(
                    tokenRetriever: provider.GetRequiredService<LocalUserAccessTokenRetriever>(),
                    dPoPNonceStore: provider.GetRequiredService<IDPoPNonceStore>(),
                    dPoPProofService: provider.GetRequiredService<IDPoPProofService>(),
                    logger: provider.GetRequiredService<ILogger<AccessTokenRequestHandler>>()));
            }
        }
    }
}
