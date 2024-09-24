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

using Duende.AccessTokenManagement.OpenIdConnect;
using System;
using System.Collections.Concurrent;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Etherna.Authentication.Native
{
    public sealed class LocalUserTokenStore : IUserTokenStore
    {
        // Fields.
        private readonly ConcurrentDictionary<string, UserToken> tokenDictionary = new();

        // Methods.
        public Task ClearTokenAsync(ClaimsPrincipal user, UserTokenRequestParameters? parameters = null)
        {
            ArgumentNullException.ThrowIfNull(user, nameof(user));

            var sub = user.FindFirst("sub")?.Value ?? throw new InvalidOperationException("no sub claim");

            tokenDictionary.TryRemove(sub, out _);
            return Task.CompletedTask;
        }

        public Task<UserToken> GetTokenAsync(ClaimsPrincipal user, UserTokenRequestParameters? parameters = null)
        {
            ArgumentNullException.ThrowIfNull(user, nameof(user));

            var sub = user.FindFirst("sub")?.Value ?? throw new InvalidOperationException("no sub claim");

            if (tokenDictionary.TryGetValue(sub, out var value))
                return Task.FromResult(value);

            return Task.FromResult(new UserToken { Error = "not found" });
        }

        public Task StoreTokenAsync(ClaimsPrincipal user, UserToken token, UserTokenRequestParameters? parameters = null)
        {
            ArgumentNullException.ThrowIfNull(user, nameof(user));

            var sub = user.FindFirst("sub")?.Value ?? throw new InvalidOperationException("no sub claim");
            tokenDictionary[sub] = token;

            return Task.CompletedTask;
        }
    }
}
