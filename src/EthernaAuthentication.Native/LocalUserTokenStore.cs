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
using System;
using System.Collections.Concurrent;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace Etherna.Authentication.Native
{
    public sealed class LocalUserTokenStore : IUserTokenStore
    {
        // Fields.
        private readonly ConcurrentDictionary<string, TokenForParameters> tokenDictionary = new();

        // Methods.
        public Task ClearTokenAsync(
            ClaimsPrincipal user,
            UserTokenRequestParameters? parameters = null,
            CancellationToken ct = new())
        {
            ArgumentNullException.ThrowIfNull(user);

            var sub = user.FindFirst("sub")?.Value ?? throw new InvalidOperationException("no sub claim");

            tokenDictionary.TryRemove(sub, out _);
            return Task.CompletedTask;
        }

        public Task<TokenResult<TokenForParameters>> GetTokenAsync(
            ClaimsPrincipal user,
            UserTokenRequestParameters? parameters = null,
            CancellationToken ct = new())
        {
            ArgumentNullException.ThrowIfNull(user);

            var sub = user.FindFirst("sub")?.Value ?? throw new InvalidOperationException("no sub claim");

            if (tokenDictionary.TryGetValue(sub, out var value))
                return Task.FromResult(TokenResult.Success(value));

            return Task.FromResult((TokenResult<TokenForParameters>)TokenResult.Failure("not found"));
        }

        public Task StoreTokenAsync(
            ClaimsPrincipal user,
            UserToken token,
            UserTokenRequestParameters? parameters = null,
            CancellationToken ct = new())
        {
            ArgumentNullException.ThrowIfNull(token);
            ArgumentNullException.ThrowIfNull(user);

            var sub = user.FindFirst("sub")?.Value ?? throw new InvalidOperationException("no sub claim");
            tokenDictionary[sub] = new TokenForParameters(
                token,
                token.RefreshToken == null
                    ? null
                    : new UserRefreshToken(token.RefreshToken.Value, token.DPoPJsonWebKey)
            );

            return Task.CompletedTask;
        }
    }
}
