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

using IdentityModel.Client;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Xunit;

namespace Etherna.Authentication
{
    public class EthernaOpenIdConnectClientBaseTest
    {
        // Internal classes.
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

        private sealed class TestOidcClient(
            IDiscoveryDocumentService discoveryDocumentService,
            IEnumerable<Claim> principalClaims)
            : EthernaOpenIdConnectClientBase(discoveryDocumentService)
        {
            protected override IEnumerable<Claim> GetCurrentUserClaims() => principalClaims;
            protected override Task<string> GetUserAccessTokenAsync() => Task.FromResult("testAccessToken");
            protected override IEnumerable<Claim> TryGetCurrentUserClaims() => principalClaims;
            protected override Task<string?> TryGetUserAccessTokenAsync() => Task.FromResult<string?>("testAccessToken");
        }

        // Tests.
        [Fact]
        public async Task TryGetClaimWithMachinePrincipalReturnsNullWithoutUserinfoFallback()
        {
            var discoveryService = new RecordingDiscoveryDocumentService();
            var client = new TestOidcClient(discoveryService,
            [
                new Claim(EthernaClaimTypes.ClientId, "testClientId"),
                new Claim(EthernaClaimTypes.Scope, "userApi.gateway")
            ]);

            var etherAddress = await client.TryGetEtherAddressAsync();

            Assert.Null(etherAddress);
            Assert.False(discoveryService.UserinfoFallbackEntered);
        }

        [Fact]
        public async Task GetClaimWithMachinePrincipalThrowsWithoutUserinfoFallback()
        {
            var discoveryService = new RecordingDiscoveryDocumentService();
            var client = new TestOidcClient(discoveryService,
            [
                new Claim(EthernaClaimTypes.ClientId, "testClientId")
            ]);

            await Assert.ThrowsAsync<KeyNotFoundException>(client.GetEtherAddressAsync);
            Assert.False(discoveryService.UserinfoFallbackEntered);
        }

        [Fact]
        public async Task TryGetClaimWithAnonymousPrincipalReturnsNullWithoutUserinfoFallback()
        {
            var discoveryService = new RecordingDiscoveryDocumentService();
            var client = new TestOidcClient(discoveryService, []);

            var etherAddress = await client.TryGetEtherAddressAsync();

            Assert.Null(etherAddress);
            Assert.False(discoveryService.UserinfoFallbackEntered);
        }

        [Theory]
        [InlineData(EthernaClaimTypes.UserId)]     //raw jwt subject
        [InlineData(ClaimTypes.NameIdentifier)]    //subject mapped by .NET claim mapping
        public async Task TryGetClaimWithUserPrincipalFallsBackToUserinfo(string subjectClaimType)
        {
            var discoveryService = new RecordingDiscoveryDocumentService();
            var client = new TestOidcClient(discoveryService,
            [
                new Claim(subjectClaimType, "testUserId"),
                new Claim(EthernaClaimTypes.ClientId, "testClientId")
            ]);

            await Assert.ThrowsAsync<UserinfoFallbackEnteredException>(client.TryGetEtherAddressAsync);
            Assert.True(discoveryService.UserinfoFallbackEntered);
        }

        [Fact]
        public async Task TryGetClaimWithClaimInPrincipalReturnsItWithoutUserinfoFallback()
        {
            var discoveryService = new RecordingDiscoveryDocumentService();
            var client = new TestOidcClient(discoveryService,
            [
                new Claim(EthernaClaimTypes.ClientId, "testClientId"),
                new Claim(EthernaClaimTypes.EtherAddress, "0x0123456789012345678901234567890123456789")
            ]);

            var etherAddress = await client.TryGetEtherAddressAsync();

            Assert.Equal("0x0123456789012345678901234567890123456789", etherAddress);
            Assert.False(discoveryService.UserinfoFallbackEntered);
        }

        [Fact]
        public async Task HasScopesWithMachinePrincipalReadsScopesWithoutUserinfoFallback()
        {
            var discoveryService = new RecordingDiscoveryDocumentService();
            var client = new TestOidcClient(discoveryService,
            [
                new Claim(EthernaClaimTypes.ClientId, "testClientId"),
                new Claim(EthernaClaimTypes.Scope, "userApi.gateway")
            ]);

            Assert.True(await client.HasScopesAsync("userApi.gateway"));
            Assert.False(await client.HasScopesAsync("userApi.credit"));
            Assert.False(discoveryService.UserinfoFallbackEntered);
        }
    }
}
