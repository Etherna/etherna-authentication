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
