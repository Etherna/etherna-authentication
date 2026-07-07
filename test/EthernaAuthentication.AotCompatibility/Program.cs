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

namespace Etherna.Authentication.AotCompatibility
{
    using Etherna.Authentication;
    using Etherna.Authentication.AspNetCore;
    using Etherna.Authentication.ClientCredentials;
    using Etherna.Authentication.Native;
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.Extensions.DependencyInjection;
    using System;
    using System.Net.Http;
    using System.Security.Claims;
    using System.Threading.Tasks;

    // Native AOT compatibility probe for the EthernaAuthentication libraries. The actual compatibility
    // gate is the ILC publish (see the .csproj and CI): publishing this app fails on any trim/AOT warning.
    // This entry point additionally proves, at runtime, that the most AOT-sensitive paths work once
    // compiled ahead-of-time: claim deserialization through the source-generated JSON context, and the
    // full dependency injection graphs of the three client packages (options, token management, caching),
    // which rely on infrastructure that is a classic AOT failure area.
    internal static class Program
    {
        // Consts.
        private const string Authority = "https://sso.example.com";

        // Methods.
        public static async Task<int> Main()
        {
            var failures =
                await VerifyClaimJsonDeserializationAsync().ConfigureAwait(false) +
                await VerifyAspNetCoreRegistrationAsync().ConfigureAwait(false) +
                await VerifyClientCredentialsRegistrationAsync().ConfigureAwait(false) +
                await VerifyNativeRegistrationAsync().ConfigureAwait(false);

            Console.WriteLine(failures == 0 ? "AOT smoke test PASSED" : $"AOT smoke test FAILED ({failures})");
            return failures;
        }

        // Helpers.
        private static async Task<int> VerifyClaimJsonDeserializationAsync()
        {
            // A NotSupportedException here would mean the JsonTypeInfo metadata was missing (the classic AOT failure mode).
            try
            {
                var client = new CannedClaimsClient(
                    new Claim(EthernaClaimTypes.EtherPreviousAddresses, """["0x0000000000000000000000000000000000000001","0x0000000000000000000000000000000000000002"]"""),
                    new Claim(EthernaClaimTypes.Role_Dotnet, "probeRole0"),
                    new Claim(EthernaClaimTypes.Role_Dotnet, "probeRole1"),
                    new Claim(EthernaClaimTypes.Username, "probeUser"));

                var prevAddresses = await client.GetEtherPrevAddressesAsync().ConfigureAwait(false);
                if (prevAddresses.Length != 2)
                    throw new InvalidOperationException($"Unexpected previous addresses count {prevAddresses.Length}.");

                var roles = await client.GetRolesAsync().ConfigureAwait(false);
                if (roles.Length != 2 || roles[0] != "probeRole0" || roles[1] != "probeRole1")
                    throw new InvalidOperationException("Unexpected roles.");

                Console.WriteLine($"[ok] json: deserialized {prevAddresses.Length} previous addresses via source-generated context");
                return 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[FAIL] json: {ex.GetType().Name}: {ex.Message}");
                return 1;
            }
        }

        private static async Task<int> VerifyAspNetCoreRegistrationAsync()
        {
            try
            {
                var services = new ServiceCollection();
                services.AddAuthentication(EthernaDefaults.AuthenticationScheme)
                    .AddEthernaOpenIdConnect(options =>
                    {
                        options.Authority = Authority;
                        options.ClientId = "probeClientId";
                        options.SaveTokens = true;
                    });

                await using var provider = services.BuildServiceProvider();
                var scheme = await provider.GetRequiredService<IAuthenticationSchemeProvider>()
                    .GetSchemeAsync(EthernaDefaults.AuthenticationScheme).ConfigureAwait(false) ??
                    throw new InvalidOperationException("Etherna authentication scheme not registered.");

                using var scope = provider.CreateScope();
                _ = scope.ServiceProvider.GetRequiredService<IEthernaOpenIdConnectClient>();

                Console.WriteLine($"[ok] aspnetcore: registered scheme \"{scheme.Name}\" and resolved oidc client");
                return 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[FAIL] aspnetcore: {ex.GetType().Name}: {ex.Message}");
                return 1;
            }
        }

        private static async Task<int> VerifyClientCredentialsRegistrationAsync()
        {
            try
            {
                var services = new ServiceCollection();
                services.AddEthernaClientCredentials(new Uri(Authority))
                    .AddClient(
                        "probeTokenClient",
                        "probeClientId",
                        "probeClientSecret",
                        ["probeScope"],
                        "probeHttpClient");

                await using var provider = services.BuildServiceProvider();

                // Building the managed client materializes the whole token management handler pipeline.
                using var httpClient = provider.GetRequiredService<IHttpClientFactory>().CreateClient("probeHttpClient");

                Console.WriteLine("[ok] clientcredentials: resolved managed http client with token management pipeline");
                return 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[FAIL] clientcredentials: {ex.GetType().Name}: {ex.Message}");
                return 1;
            }
        }

        private static async Task<int> VerifyNativeRegistrationAsync()
        {
            try
            {
                var services = new ServiceCollection();
                services.AddEthernaOidcClient(
                    Authority,
                    "probeClientId",
                    null,
                    11420,
                    [EthernaScopes.UserApiCredit],
                    "probeHttpClient");

                await using var provider = services.BuildServiceProvider();

                // Resolving the client builds the sign in services of both flows, which pull the OpenId
                // Connect options pipeline (post-configuration, data protection, configuration manager).
                var client = provider.GetRequiredService<IEthernaOpenIdConnectClient>();

                // Unauthenticated user: must return null without touching the network.
                var clientId = await client.TryGetClientIdAsync().ConfigureAwait(false);
                if (clientId is not null)
                    throw new InvalidOperationException("Unexpected client id for unauthenticated user.");

                using var httpClient = provider.GetRequiredService<IHttpClientFactory>().CreateClient("probeHttpClient");

                Console.WriteLine("[ok] native: resolved oidc client and managed http client");
                return 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[FAIL] native: {ex.GetType().Name}: {ex.Message}");
                return 1;
            }
        }

        // Test client returning canned user claims, so the probe can drive the claim
        // deserialization paths without a live SSO server.
        private sealed class CannedClaimsClient(params Claim[] claims)
            : EthernaOpenIdConnectClientBase(new DiscoveryDocumentService(Authority))
        {
            protected override System.Collections.Generic.IEnumerable<Claim> GetCurrentUserClaims() => claims;
            protected override Task<string> GetUserAccessTokenAsync() => throw new InvalidOperationException();
            protected override System.Collections.Generic.IEnumerable<Claim> TryGetCurrentUserClaims() => claims;
            protected override Task<string?> TryGetUserAccessTokenAsync() => Task.FromResult<string?>(null);
        }
    }
}
