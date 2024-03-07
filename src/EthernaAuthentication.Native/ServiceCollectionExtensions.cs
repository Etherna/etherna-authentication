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
using Etherna.Authentication.Native.CodeFlow;
using Etherna.Authentication.Native.PasswordFlow;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;
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
                    options.Scope.Add("ether_accounts");
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
                    options.Scope.Add("ether_accounts");
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
        }

        // Helpers.
        private static void AddCommonServices(
            IServiceCollection services,
            Action<OpenIdConnectOptions> configureOidcOptions,
            string? managedHttpClientName,
            Action<HttpClient>? configureManagedHttpClient)
        {
            // Check conditions.
            if (services is null)
                throw new ArgumentNullException(nameof(services));
            if (configureOidcOptions is null)
                throw new ArgumentNullException(nameof(configureOidcOptions));

            var options = new OpenIdConnectOptions();
            configureOidcOptions(options);

            if (options.Authority is null)
                throw new InvalidOperationException("Authority can't be null");

            // Register memory cache to keep tokens.
            services.AddDistributedMemoryCache();
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

                services.AddSingleton<LocalUserAccessTokenHandler>();
                httpClientBuilder.AddHttpMessageHandler<LocalUserAccessTokenHandler>();
            }
        }
    }
}
