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

using Duende.IdentityModel.Client;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Etherna.Authentication
{
    public class EthernaOpenIdConnectClientBaseTest
    {
        // Enums.
        public enum UserinfoAnswer
        {
            Forbidden,
            Malformed,
            ServerError,
            Silent,
            Success,
            Unauthorized
        }

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

        private sealed class RecordingLogger : ILogger
        {
            public List<LogLevel> LoggedLevels { get; } = [];

            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
            public bool IsEnabled(LogLevel logLevel) => true;
            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
                LoggedLevels.Add(logLevel);
        }

        private sealed class StubDiscoveryDocumentService(
            Uri userinfoEndpoint)
            : IDiscoveryDocumentService
        {
            public async Task<DiscoveryDocumentResponse> GetDiscoveryDocumentAsync()
            {
                using var httpResponse = new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent($$"""{"userinfo_endpoint":"{{userinfoEndpoint}}"}""")
                };
                return await ProtocolResponse.FromHttpResponseAsync<DiscoveryDocumentResponse>(
                    httpResponse,
                    new DiscoveryPolicy
                    {
                        Authority = userinfoEndpoint.GetLeftPart(UriPartial.Authority),
                        RequireKeySet = false,
                        ValidateIssuerName = false
                    });
            }
        }

        private sealed class TestOidcClient(
            IDiscoveryDocumentService discoveryDocumentService,
            IEnumerable<Claim> principalClaims,
            ILogger? logger = null,
            TimeSpan? userInfoFailureRetryDelay = null,
            TimeSpan? userInfoTimeout = null)
            : EthernaOpenIdConnectClientBase(discoveryDocumentService, logger ?? NullLogger.Instance)
        {
            // The signed in user can change during the life of a client, with its token and principal.
            public string AccessToken { get; set; } = "testAccessToken";
            public IEnumerable<Claim> PrincipalClaims { get; set; } = principalClaims;

            internal override TimeSpan UserInfoFailureRetryDelay => userInfoFailureRetryDelay ?? base.UserInfoFailureRetryDelay;
            internal override TimeSpan UserInfoTimeout => userInfoTimeout ?? base.UserInfoTimeout;

            protected override IEnumerable<Claim> GetCurrentUserClaims() => PrincipalClaims;
            protected override Task<string> GetUserAccessTokenAsync() => Task.FromResult(AccessToken);
            protected override IEnumerable<Claim> TryGetCurrentUserClaims() => PrincipalClaims;
            protected override Task<string?> TryGetUserAccessTokenAsync() => Task.FromResult<string?>(AccessToken);
        }

        // Loopback userinfo endpoint: the client under test owns its http client, so the
        // endpoint answers are driven from a real socket. Counts the requests it receives,
        // and answers the claims of the access token each one carries.
        private sealed class UserinfoEndpointStub : IDisposable
        {
            // Consts.
            private const string BearerHeaderPrefix = "Authorization: Bearer ";

            // Fields.
            private readonly CancellationTokenSource disposeSource = new();
            private readonly TcpListener listener = new(IPAddress.Loopback, 0);
            private int requestsCount;

            // Constructor and dispose.
            public UserinfoEndpointStub(UserinfoAnswer answer)
            {
                Answer = answer;
                listener.Start();
                _ = AcceptAsync();
            }

            public void Dispose()
            {
                disposeSource.Cancel();
                disposeSource.Dispose();
                listener.Dispose();
            }

            // Properties.
            public Uri Address => new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/connect/userinfo");
            public UserinfoAnswer Answer { get; set; }
            public int RequestsCount => Volatile.Read(ref requestsCount);

            // Helpers.
            private async Task AcceptAsync()
            {
                try
                {
                    while (true)
                        _ = ServeAsync(await listener.AcceptTcpClientAsync(disposeSource.Token));
                }
                catch (OperationCanceledException) { } //stub disposed
            }

            private static string BuildResponse(string status, string jsonBody) =>
                $"HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {jsonBody.Length}\r\nConnection: close\r\n\r\n{jsonBody}";

            private async Task ServeAsync(TcpClient tcpClient)
            {
                using var connection = tcpClient;
                using var stream = tcpClient.GetStream();
                using var reader = new StreamReader(stream, Encoding.ASCII);

                //a bearer GET has no body: the request ends with the headers
                var accessToken = "";
                string? header;
                while (!string.IsNullOrEmpty(header = await reader.ReadLineAsync()))
                    if (header.StartsWith(BearerHeaderPrefix, StringComparison.OrdinalIgnoreCase))
                        accessToken = header[BearerHeaderPrefix.Length..];
                Interlocked.Increment(ref requestsCount);

                if (Answer is UserinfoAnswer.Silent)
                {
                    //hold the connection without answering, until the stub is disposed
                    try { await Task.Delay(Timeout.Infinite, disposeSource.Token); }
                    catch (OperationCanceledException) { }
                    return;
                }

                await stream.WriteAsync(Encoding.ASCII.GetBytes(Answer switch
                {
                    UserinfoAnswer.Forbidden => BuildResponse("403 Forbidden", ""),
                    UserinfoAnswer.Malformed => "not an http response\r\n\r\n",
                    UserinfoAnswer.ServerError => BuildResponse("503 Service Unavailable", ""),
                    UserinfoAnswer.Success => BuildResponse("200 OK", $$"""{"sub":"userIdOf:{{accessToken}}","preferred_username":"usernameOf:{{accessToken}}"}"""),
                    UserinfoAnswer.Unauthorized => BuildResponse("401 Unauthorized", ""),
                    _ => throw new InvalidOperationException()
                }));
            }
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

        [Fact]
        public async Task GetRolesWithMultipleDotnetRoleClaimsReturnsAllRoles()
        {
            var discoveryService = new RecordingDiscoveryDocumentService();
            var client = new TestOidcClient(discoveryService,
            [
                new Claim(EthernaClaimTypes.UserId, "testUserId"),
                new Claim(EthernaClaimTypes.Role_Dotnet, "testRole0"),
                new Claim(EthernaClaimTypes.Role_Dotnet, "testRole1")
            ]);

            var roles = await client.GetRolesAsync();

            Assert.Equal(["testRole0", "testRole1"], roles);
            Assert.False(discoveryService.UserinfoFallbackEntered);
        }

        [Fact]
        public async Task GetRolesWithMultipleIdentityModelRoleClaimsReturnsAllRoles()
        {
            var discoveryService = new RecordingDiscoveryDocumentService();
            var client = new TestOidcClient(discoveryService,
            [
                new Claim(EthernaClaimTypes.ClientId, "testClientId"),
                new Claim(EthernaClaimTypes.Role_IdentityModel, "testRole0"),
                new Claim(EthernaClaimTypes.Role_IdentityModel, "testRole1")
            ]);

            var roles = await client.GetRolesAsync();

            Assert.Equal(["testRole0", "testRole1"], roles);
            Assert.False(discoveryService.UserinfoFallbackEntered);
        }

        [Fact]
        public async Task GetRolesWithBothRoleClaimTypesPrefersDotnetClaims()
        {
            var discoveryService = new RecordingDiscoveryDocumentService();
            var client = new TestOidcClient(discoveryService,
            [
                new Claim(EthernaClaimTypes.UserId, "testUserId"),
                new Claim(EthernaClaimTypes.Role_Dotnet, "dotnetRole"),
                new Claim(EthernaClaimTypes.Role_IdentityModel, "identityModelRole")
            ]);

            var roles = await client.GetRolesAsync();

            Assert.Equal(["dotnetRole"], roles);
            Assert.False(discoveryService.UserinfoFallbackEntered);
        }

        [Fact]
        public async Task TryGetRolesWithMachinePrincipalWithoutRolesReturnsNullWithoutUserinfoFallback()
        {
            var discoveryService = new RecordingDiscoveryDocumentService();
            var client = new TestOidcClient(discoveryService,
            [
                new Claim(EthernaClaimTypes.ClientId, "testClientId")
            ]);

            var roles = await client.TryGetRolesAsync();

            Assert.Null(roles);
            Assert.False(discoveryService.UserinfoFallbackEntered);
        }

        [Theory]
        [InlineData(UserinfoAnswer.Malformed)]       //failed request: the response carries null claims
        [InlineData(UserinfoAnswer.ServerError)]
        [InlineData(UserinfoAnswer.Silent)]          //no answer within the timeout
        [InlineData(UserinfoAnswer.Unauthorized)]    //e.g. token of a user deleted after its issuance
        public async Task TryGetClaimWithFailingUserinfoReturnsNullAskingEndpointOnce(UserinfoAnswer answer)
        {
            using var userinfoEndpoint = new UserinfoEndpointStub(answer);
            var logger = new RecordingLogger();
            var client = new TestOidcClient(new StubDiscoveryDocumentService(userinfoEndpoint.Address),
            [
                new Claim(EthernaClaimTypes.UserId, "testUserId")
            ], logger, userInfoTimeout: answer is UserinfoAnswer.Silent ? TimeSpan.FromMilliseconds(100) : null);

            var username = await client.TryGetUsernameAsync();
            var roles = await client.TryGetRolesAsync();

            Assert.Null(username);
            Assert.Null(roles);
            Assert.Equal(1, userinfoEndpoint.RequestsCount);
            Assert.Equal([LogLevel.Warning], logger.LoggedLevels);
        }

        [Fact]
        public async Task TryGetClaimWithClaimInUserinfoReturnsItAskingEndpointOnce()
        {
            using var userinfoEndpoint = new UserinfoEndpointStub(UserinfoAnswer.Success);
            var logger = new RecordingLogger();
            var client = new TestOidcClient(new StubDiscoveryDocumentService(userinfoEndpoint.Address),
            [
                new Claim(EthernaClaimTypes.UserId, "testUserId")
            ], logger);

            var username = await client.TryGetUsernameAsync();
            var etherAddress = await client.TryGetEtherAddressAsync();

            Assert.Equal("usernameOf:testAccessToken", username);
            Assert.Null(etherAddress);
            Assert.Equal(1, userinfoEndpoint.RequestsCount);
            Assert.Empty(logger.LoggedLevels);
        }

        [Theory]
        [InlineData(UserinfoAnswer.Malformed, 2)]
        [InlineData(UserinfoAnswer.ServerError, 2)]
        [InlineData(UserinfoAnswer.Silent, 2)]
        [InlineData(UserinfoAnswer.Unauthorized, 1)]    //an answer about the token: holds as long as the token
        public async Task TryGetClaimWithFailingUserinfoAsksEndpointAgainOnlyAfterTransientFailure(UserinfoAnswer answer, int expectedRequests)
        {
            using var userinfoEndpoint = new UserinfoEndpointStub(answer);
            var client = new TestOidcClient(new StubDiscoveryDocumentService(userinfoEndpoint.Address),
            [
                new Claim(EthernaClaimTypes.UserId, "testUserId")
            ],
            userInfoFailureRetryDelay: TimeSpan.Zero,
            userInfoTimeout: answer is UserinfoAnswer.Silent ? TimeSpan.FromMilliseconds(100) : null);

            await client.TryGetUsernameAsync();
            await client.TryGetUsernameAsync();

            Assert.Equal(expectedRequests, userinfoEndpoint.RequestsCount);
        }

        [Fact]
        public async Task TryGetClaimAfterAccessTokenChangeAsksEndpointAgainWithNewToken()
        {
            using var userinfoEndpoint = new UserinfoEndpointStub(UserinfoAnswer.Success);
            var client = new TestOidcClient(new StubDiscoveryDocumentService(userinfoEndpoint.Address),
            [
                new Claim(EthernaClaimTypes.UserId, "firstUserId")
            ])
            {
                AccessToken = "firstAccessToken"
            };

            var firstUsername = await client.TryGetUsernameAsync();

            client.AccessToken = "secondAccessToken";
            client.PrincipalClaims = [new Claim(EthernaClaimTypes.UserId, "secondUserId")];
            var secondUsername = await client.TryGetUsernameAsync();
            await client.TryGetEtherAddressAsync();

            Assert.Equal("usernameOf:firstAccessToken", firstUsername);
            Assert.Equal("usernameOf:secondAccessToken", secondUsername);
            Assert.Equal(2, userinfoEndpoint.RequestsCount);
        }

        [Fact]
        public async Task IsUserTokenRejectedAfterAccessTokenChangeTellsAnswerToNewToken()
        {
            using var userinfoEndpoint = new UserinfoEndpointStub(UserinfoAnswer.Unauthorized);
            var client = new TestOidcClient(new StubDiscoveryDocumentService(userinfoEndpoint.Address),
            [
                new Claim(EthernaClaimTypes.UserId, "testUserId")
            ])
            {
                AccessToken = "rejectedAccessToken"
            };

            var isFirstTokenRejected = await client.IsUserTokenRejectedAsync();

            userinfoEndpoint.Answer = UserinfoAnswer.Success;
            client.AccessToken = "refreshedAccessToken";
            var isSecondTokenRejected = await client.IsUserTokenRejectedAsync();
            var username = await client.TryGetUsernameAsync();

            Assert.True(isFirstTokenRejected);
            Assert.False(isSecondTokenRejected);
            Assert.Equal("usernameOf:refreshedAccessToken", username);
            Assert.Equal(2, userinfoEndpoint.RequestsCount);
        }

        [Theory]
        [InlineData(UserinfoAnswer.Forbidden, false)]      //an error, but not about the token validity
        [InlineData(UserinfoAnswer.Unauthorized, true)]
        public async Task IsUserTokenRejectedTellsUnauthorizedAnswerSharingUserinfoLookup(UserinfoAnswer answer, bool expected)
        {
            using var userinfoEndpoint = new UserinfoEndpointStub(answer);
            var client = new TestOidcClient(new StubDiscoveryDocumentService(userinfoEndpoint.Address),
            [
                new Claim(EthernaClaimTypes.UserId, "testUserId")
            ]);

            var username = await client.TryGetUsernameAsync();
            var isUserTokenRejected = await client.IsUserTokenRejectedAsync();

            Assert.Null(username);
            Assert.Equal(expected, isUserTokenRejected);
            Assert.Equal(1, userinfoEndpoint.RequestsCount);
        }

        [Fact]
        public async Task IsUserTokenRejectedWithMachinePrincipalReturnsFalseWithoutUserinfoFallback()
        {
            var discoveryService = new RecordingDiscoveryDocumentService();
            var client = new TestOidcClient(discoveryService,
            [
                new Claim(EthernaClaimTypes.ClientId, "testClientId")
            ]);

            Assert.False(await client.IsUserTokenRejectedAsync());
            Assert.False(discoveryService.UserinfoFallbackEntered);
        }
    }
}
