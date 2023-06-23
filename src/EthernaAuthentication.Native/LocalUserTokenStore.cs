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
            if (user is null)
                throw new ArgumentNullException(nameof(user));

            var sub = user.FindFirst("sub")?.Value ?? throw new InvalidOperationException("no sub claim");

            tokenDictionary.TryRemove(sub, out _);
            return Task.CompletedTask;
        }

        public Task<UserToken> GetTokenAsync(ClaimsPrincipal user, UserTokenRequestParameters? parameters = null)
        {
            if (user is null)
                throw new ArgumentNullException(nameof(user));

            var sub = user.FindFirst("sub")?.Value ?? throw new InvalidOperationException("no sub claim");

            if (tokenDictionary.TryGetValue(sub, out var value))
                return Task.FromResult(value);

            return Task.FromResult(new UserToken { Error = "not found" });
        }

        public Task StoreTokenAsync(ClaimsPrincipal user, UserToken token, UserTokenRequestParameters? parameters = null)
        {
            if (user is null)
                throw new ArgumentNullException(nameof(user));

            var sub = user.FindFirst("sub")?.Value ?? throw new InvalidOperationException("no sub claim");
            tokenDictionary[sub] = token;

            return Task.CompletedTask;
        }
    }
}
