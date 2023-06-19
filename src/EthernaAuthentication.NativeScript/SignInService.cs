using IdentityModel.Client;
using System;
using System.Net.Http;
using System.Threading.Tasks;

namespace Etherna.Authentication.NativeScript
{
    public static class SignInService
    {
        public static async Task<UserInfoResponse> PasswordFlowGetUserInfoAsync(
            Uri ssoBaseUrl,
            string accessToken)
        {
            if (ssoBaseUrl is null)
                throw new ArgumentNullException(nameof(ssoBaseUrl));
            if (string.IsNullOrWhiteSpace(accessToken))
                throw new ArgumentException($"'{nameof(accessToken)}' cannot be null or whitespace.", nameof(accessToken));

            using var client = new HttpClient();
            using var request = new UserInfoRequest
            {
                Address = ssoBaseUrl.AbsoluteUri + "connect/userinfo",
                Token = accessToken
            };

            return await client.GetUserInfoAsync(request).ConfigureAwait(false);
        }

        public static async Task<TokenResponse> PasswordFlowSignInAsync(
            Uri ssoBaseUrl,
            string apiKey,
            string scope)
        {
            if (ssoBaseUrl is null)
                throw new ArgumentNullException(nameof(ssoBaseUrl));
            if (apiKey is null)
                throw new ArgumentNullException(nameof(apiKey));
            if (string.IsNullOrWhiteSpace(scope))
                throw new ArgumentException($"'{nameof(scope)}' cannot be null or whitespace.", nameof(scope));

            var splitApiKey = apiKey.Split('.');
            if (splitApiKey.Length != 2)
                throw new ArgumentException("Invalid api key", nameof(apiKey));

            using var client = new HttpClient();
            using var request = new PasswordTokenRequest
            {
                Address = ssoBaseUrl.AbsoluteUri + "connect/token",

                ClientId = "apiKeyClientId",
                Scope = scope,

                UserName = splitApiKey[0],
                Password = splitApiKey[1]
            };

            return await client.RequestPasswordTokenAsync(request).ConfigureAwait(false);
        }
    }
}
