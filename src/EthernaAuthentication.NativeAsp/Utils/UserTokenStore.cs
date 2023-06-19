using Duende.AccessTokenManagement.OpenIdConnect;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Etherna.Authentication.NativeAsp.Utils
{
    internal sealed class UserTokenStore : IUserTokenStore
    {
        // Fields.
        private readonly IDictionary<ClaimsPrincipal, UserToken> tokenDictionary = new Dictionary<ClaimsPrincipal, UserToken>();

        // Methods.
        public Task ClearTokenAsync(ClaimsPrincipal user, UserTokenRequestParameters? parameters = null)
        {
            tokenDictionary.Clear();
            return Task.CompletedTask;
        }

        public Task<UserToken> GetTokenAsync(ClaimsPrincipal user, UserTokenRequestParameters? parameters = null)
        {
            if (tokenDictionary.TryGetValue(user, out var token))
                return Task.FromResult(token);
            return Task.FromResult<UserToken>(default!);
        }

        public Task StoreTokenAsync(ClaimsPrincipal user, UserToken token, UserTokenRequestParameters? parameters = null)
        {
            tokenDictionary[user] = token;
            return Task.CompletedTask;
        }
    }
}
