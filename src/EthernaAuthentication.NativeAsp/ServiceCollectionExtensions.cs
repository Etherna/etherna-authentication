using Duende.AccessTokenManagement.OpenIdConnect;
using Etherna.Authentication.AspNetCore;
using Etherna.Authentication.NativeAsp.Utils;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Net.Http;

namespace Etherna.Authentication.NativeAsp
{
    public static class ServiceCollectionExtensions
    {
        public static void AddEthernaOpenIdConnectClient(
            this IServiceCollection services,
            Action<OpenIdConnectOptions> configureOidcOptions,
            string? managedHttpClientName = null,
            Action<HttpClient>? configureManagedHttpClient = null)
        {
            // Register memory cache to keep tokens.
            services.AddSingleton<IUserTokenStore, LocalUserTokenStore>();

            // Add Etherna OpenID Connect.
            services.AddAuthentication()
                .AddEthernaOpenIdConnect(configureOidcOptions);

            // Adds services for token management.
            services.AddOpenIdConnectAccessTokenManagement();

            // Register HTTP client that uses the managed user access token.
            if (managedHttpClientName is not null)
                services.AddUserAccessTokenHttpClient(
                    managedHttpClientName,
                    configureClient: configureManagedHttpClient);
        }
    }
}
