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
using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Etherna.Authentication.AspNetCore
{
    public class EthernaOpenIdConnectClientTest
    {
        // Internal classes.
        public sealed class ManagedLookupEnteredException : Exception;
        public sealed class UserinfoFallbackEnteredException : Exception;

        private sealed class RecordingDiscoveryDocumentService : IDiscoveryDocumentService
        {
            public bool UserinfoFallbackEntered { get; private set; }

            // The discovery document is the first step of the userinfo fallback: record the
            // attempt and interrupt the test there, before any network call could happen.
            public Task<DiscoveryDocumentResponse> GetDiscoveryDocumentAsync()
            {
                UserinfoFallbackEntered = true;
                throw new UserinfoFallbackEnteredException();
            }
        }

        private sealed class RecordingUserTokenManager : IUserTokenManager
        {
            public bool ManagedLookupEntered { get; private set; }

            // The managed lookup outcome is not under test, only whether it gets invoked:
            // record the attempt and interrupt the test there.
            public Task<TokenResult<UserToken>> GetAccessTokenAsync(
                ClaimsPrincipal user,
                UserTokenRequestParameters? parameters = null,
                CancellationToken cancellationToken = default)
            {
                ManagedLookupEntered = true;
                throw new ManagedLookupEnteredException();
            }

            public Task RevokeRefreshTokenAsync(
                ClaimsPrincipal user,
                UserTokenRequestParameters? parameters = null,
                CancellationToken cancellationToken = default) =>
                throw new NotSupportedException();
        }

        private sealed class StaticAuthenticationService(AuthenticationProperties sessionProperties)
            : IAuthenticationService
        {
            public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme) =>
                Task.FromResult(AuthenticateResult.Success(
                    new AuthenticationTicket(context.User, sessionProperties, "TestScheme")));

            public Task ChallengeAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) =>
                throw new NotSupportedException();

            public Task ForbidAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) =>
                throw new NotSupportedException();

            public Task SignInAsync(HttpContext context, string? scheme, ClaimsPrincipal principal, AuthenticationProperties? properties) =>
                throw new NotSupportedException();

            public Task SignOutAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) =>
                throw new NotSupportedException();
        }

        // Fields.
        private readonly RecordingDiscoveryDocumentService discoveryService = new();
        private readonly RecordingUserTokenManager userTokenManager = new();

        // Helpers.
        private EthernaOpenIdConnectClient CreateClient(
            IEnumerable<Claim> principalClaims,
            params (string Name, string Value)[] sessionTokens)
        {
            var sessionProperties = new AuthenticationProperties();
            sessionProperties.StoreTokens(sessionTokens.Select(
                t => new AuthenticationToken { Name = t.Name, Value = t.Value }));

            var services = new ServiceCollection();
            services.AddSingleton<IAuthenticationService>(new StaticAuthenticationService(sessionProperties));
            services.AddSingleton<IUserTokenManager>(userTokenManager);

            var httpContext = new DefaultHttpContext
            {
                RequestServices = services.BuildServiceProvider(),
                User = new ClaimsPrincipal(new ClaimsIdentity(principalClaims))
            };

            return new EthernaOpenIdConnectClient(
                discoveryService,
                new HttpContextAccessor { HttpContext = httpContext });
        }

        // Tests.
        [Fact]
        public async Task TryGetClaimWithTokenlessSessionSkipsManagedLookupAndUserinfo()
        {
            // Sessions signed in without an OpenId Connect handler, like local cookie logins
            // on the SSO server itself, carry no tokens at all.
            var client = CreateClient([new Claim(EthernaClaimTypes.UserId, "testUserId")]);

            var etherAddress = await client.TryGetEtherAddressAsync();

            Assert.Null(etherAddress);
            Assert.False(userTokenManager.ManagedLookupEntered);
            Assert.False(discoveryService.UserinfoFallbackEntered);
        }

        [Fact]
        public async Task TryGetClaimWithRefreshTokenInSessionUsesManagedLookup()
        {
            var client = CreateClient(
                [new Claim(EthernaClaimTypes.UserId, "testUserId")],
                ("access_token", "testAccessToken"),
                ("refresh_token", "testRefreshToken"));

            await Assert.ThrowsAsync<ManagedLookupEnteredException>(client.TryGetEtherAddressAsync);
            Assert.True(userTokenManager.ManagedLookupEntered);
        }

        [Fact]
        public async Task TryGetClaimWithRawAccessTokenOnlySkipsManagedLookupAndFallsBackToUserinfo()
        {
            // This is the case of requests authenticated with a plain bearer token.
            var client = CreateClient(
                [new Claim(EthernaClaimTypes.UserId, "testUserId")],
                ("access_token", "testAccessToken"));

            await Assert.ThrowsAsync<UserinfoFallbackEnteredException>(client.TryGetEtherAddressAsync);
            Assert.False(userTokenManager.ManagedLookupEntered);
            Assert.True(discoveryService.UserinfoFallbackEntered);
        }
    }
}
