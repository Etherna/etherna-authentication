using Etherna.Authentication.NativeAsp.Utils;
using IdentityModel.OidcClient;
using System;
using System.Net.Http;
using System.Threading.Tasks;

namespace Etherna.Authentication.NativeAsp
{
    public static class SignInService
    {
        public static async Task<LoginResult> CodeFlowSigIn(
            Uri ssoBaseUrl,
            string clientId,
            string scope,
            int returnUrlPort)
        {
            if (ssoBaseUrl is null)
                throw new ArgumentNullException(nameof(ssoBaseUrl));
            if (string.IsNullOrWhiteSpace(clientId))
                throw new ArgumentException($"'{nameof(clientId)}' cannot be null or whitespace.", nameof(clientId));
            if (string.IsNullOrWhiteSpace(scope))
                throw new ArgumentException($"'{nameof(scope)}' cannot be null or whitespace.", nameof(scope));

            // create a redirect URI using an available port on the loopback address.
            // requires the OP to allow random ports on 127.0.0.1 - otherwise set a static port
            var browser = new SystemBrowser(returnUrlPort);
            var redirectUri = $"http://127.0.0.1:{browser.Port}";

            var options = new OidcClientOptions
            {
                Authority = ssoBaseUrl.AbsoluteUri,
                ClientId = clientId,
                RedirectUri = redirectUri,
                Scope = scope,
                FilterClaims = false,

                Browser = browser,
                RefreshTokenInnerHttpHandler = new SocketsHttpHandler()
            };

            var oidcClient = new OidcClient(options);
            return await oidcClient.LoginAsync(new LoginRequest()).ConfigureAwait(false);
        }
    }
}
