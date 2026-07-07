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
using System.Security.Claims;
using System.Threading.Tasks;
using Xunit;

namespace Etherna.Authentication.Native
{
    public class EthernaSignInServiceTest
    {
        // Fakes.
        private sealed class FakeApiKeySignInService : IEthernaApiKeySignInService
        {
            public string AuthenticationSchemeName => EthernaNativeDefaults.ApiKeyAuthenticationScheme;
            public string? ReceivedApiKey { get; private set; }
            public ClaimsPrincipal User { get; } = BuildUser("apiKeyUser");

            public Task<ClaimsPrincipal> SignInAsync(string apiKey)
            {
                ReceivedApiKey = apiKey;
                return Task.FromResult(User);
            }
        }

        private sealed class FakeCodeSignInService : IEthernaCodeSignInService
        {
            public string AuthenticationSchemeName => EthernaNativeDefaults.CodeAuthenticationScheme;
            public int SignInCalls { get; private set; }
            public ClaimsPrincipal User { get; } = BuildUser("codeUser");

            public Task<ClaimsPrincipal> SignInAsync()
            {
                SignInCalls++;
                return Task.FromResult(User);
            }
        }

        // Fields.
        private readonly FakeApiKeySignInService apiKeySignInService = new();
        private readonly FakeCodeSignInService codeSignInService = new();
        private readonly EthernaSignInService signInService;

        // Constructor.
        public EthernaSignInServiceTest()
        {
            signInService = new EthernaSignInService(apiKeySignInService, codeSignInService);
        }

        // Tests.
        [Fact]
        public async Task GetCurrentUserAsyncFallsBackToEmptyPrincipal()
        {
            var user = await signInService.GetCurrentUserAsync();

            Assert.NotNull(user);
            Assert.Null(user.Identity);
        }

        [Fact]
        public async Task GetCurrentUserAsyncReturnsSignedInUser()
        {
            await signInService.SignInAsync();

            var user = await signInService.GetCurrentUserAsync();

            Assert.Same(codeSignInService.User, user);
        }

        [Fact]
        public void IsNotAuthenticatedByDefault()
        {
            Assert.False(signInService.IsAuthenticated);
            Assert.Null(signInService.CurrentAuthenticationSchemeName);
            Assert.Null(signInService.CurrentUser);
        }

        [Fact]
        public async Task SignInWithApiKeyUsesPasswordFlow()
        {
            await signInService.SignInAsync("myUser.myKey");

            Assert.Equal("myUser.myKey", apiKeySignInService.ReceivedApiKey);
            Assert.Equal(EthernaNativeDefaults.ApiKeyAuthenticationScheme, signInService.CurrentAuthenticationSchemeName);
            Assert.Same(apiKeySignInService.User, signInService.CurrentUser);
            Assert.True(signInService.IsAuthenticated);
        }

        [Fact]
        public async Task SignInWithoutApiKeyUsesCodeFlow()
        {
            await signInService.SignInAsync();

            Assert.Equal(1, codeSignInService.SignInCalls);
            Assert.Equal(EthernaNativeDefaults.CodeAuthenticationScheme, signInService.CurrentAuthenticationSchemeName);
            Assert.Same(codeSignInService.User, signInService.CurrentUser);
            Assert.True(signInService.IsAuthenticated);
        }

        [Fact]
        public async Task SwitchingFlowUpdatesCurrentSignIn()
        {
            await signInService.SignInAsync();
            await signInService.SignInAsync("myUser.myKey");

            Assert.Equal(EthernaNativeDefaults.ApiKeyAuthenticationScheme, signInService.CurrentAuthenticationSchemeName);
            Assert.Same(apiKeySignInService.User, signInService.CurrentUser);
        }

        // Helpers.
        private static ClaimsPrincipal BuildUser(string sub) =>
            new(new ClaimsIdentity([new Claim("sub", sub)], "test"));
    }
}
