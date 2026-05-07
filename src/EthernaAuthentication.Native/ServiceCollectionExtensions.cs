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
using System.Net.Http;

namespace Etherna.Authentication.Native
{
    public static class ServiceCollectionExtensions
    {
        public static void AddEthernaApiKeyOidcClient(
            this IServiceCollection services,
            string authority,
            string apiKey,
            IEnumerable<string> scopes,
            string? managedHttpClientName = null,
            Action<HttpClient>? configureManagedHttpClient = null)
        {
            AddCommonServices(
                services,
                options =>
                {
                    options.Authority = authority;
                    options.ClientId = "apiKeyClientId";
                    options.SaveTokens = true;
                    options.Scope.Add("offline_access");
                    options.Scope.Add(EthernaScopes.EtherAccounts);
                    foreach (var scope in scopes)
                        options.Scope.Add(scope);
                },
                managedHttpClientName,
                configureManagedHttpClient);

            // Add Etherna password flow sign in service.
            services.Configure<EthernaApiKeySignInServiceOptions>(options =>
            {
                options.ApiKey = apiKey;
            });
            services.AddSingleton<IEthernaSignInService, EthernaApiKeySignInService>();
            services.AddSingleton<IUserAccessor, EthernaApiKeySignInService>(provider =>
                (EthernaApiKeySignInService)provider.GetRequiredService<IEthernaSignInService>());
        }

        public static void AddEthernaCodeOidcClient(
            this IServiceCollection services,
            string authority,
            string clientId,
            string? clientSecret,
            int returnUrlPort,
            IEnumerable<string> scopes,
            string? managedHttpClientName = null,
            Action<HttpClient>? configureManagedHttpClient = null)
        {
            AddCommonServices(
                services,
                options =>
                {
                    options.Authority = authority;
                    options.ClientId = clientId;
                    options.ClientSecret = clientSecret;
                    options.ResponseType = "code";
                    options.SaveTokens = true;
                    options.Scope.Add("offline_access");
                    options.Scope.Add(EthernaScopes.EtherAccounts);
                    foreach (var scope in scopes)
                        options.Scope.Add(scope);
                },
                managedHttpClientName,
                configureManagedHttpClient);

            // Add Etherna code flow sign in service.
            services.Configure<EthernaCodeSignInServiceOptions>(options =>
            {
                options.ReturnUrlPort = returnUrlPort;
            });
            services.AddSingleton<IEthernaSignInService, EthernaCodeSignInService>();
            services.AddSingleton<IUserAccessor, EthernaCodeSignInService>(provider =>
                (EthernaCodeSignInService)provider.GetRequiredService<IEthernaSignInService>());
        }

        // Helpers.
        private static void AddCommonServices(
            IServiceCollection services,
            Action<OpenIdConnectOptions> configureOidcOptions,
            string? managedHttpClientName,
            Action<HttpClient>? configureManagedHttpClient)
        {
            // Check conditions.
            ArgumentNullException.ThrowIfNull(services);
            ArgumentNullException.ThrowIfNull(configureOidcOptions);

            var options = new OpenIdConnectOptions();
            configureOidcOptions(options);

            if (options.Authority is null)
                throw new InvalidOperationException("Authority can't be null");

            // Register cache to keep tokens.
            services.AddHybridCache();
            services.AddSingleton<IUserTokenStore, LocalUserTokenStore>();

            // Add Etherna OpenID Connect.
            services.AddSingleton<IDiscoveryDocumentService>(
                new DiscoveryDocumentService(options.Authority, options.RequireHttpsMetadata));
            services.AddSingleton<IEthernaOpenIdConnectClient, EthernaOpenIdConnectClient>();

            services.AddAuthentication()
                .AddOpenIdConnect(EthernaDefaults.AuthenticationScheme, EthernaDefaults.DisplayName, configureOidcOptions);

            // Adds services for token management.
            services.AddOpenIdConnectAccessTokenManagement();

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
