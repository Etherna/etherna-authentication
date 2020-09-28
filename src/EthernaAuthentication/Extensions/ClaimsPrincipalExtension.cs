using Etherna.Authentication.Consts;
using System;
using System.Linq;
using System.Security.Claims;
using System.Text.Json;

namespace Etherna.Authentication.Extensions
{
    public static class ClaimsPrincipalExtension
    {
        public static string GetClientId(this ClaimsPrincipal user)
        {
            if (user is null)
                throw new ArgumentNullException(nameof(user));

            return user.Claims.First(claim => claim.Type == DefaultClaimTypes.ClientId).Value;
        }

        public static string GetEtherAddress(this ClaimsPrincipal user)
        {
            if (user is null)
                throw new ArgumentNullException(nameof(user));

            return user.Claims.First(claim => claim.Type == DefaultClaimTypes.EtherAddress).Value;
        }

        public static string[] GetEtherPrevAddresses(this ClaimsPrincipal user)
        {
            if (user is null)
                throw new ArgumentNullException(nameof(user));

            var claim = user.Claims.First(claim => claim.Type == DefaultClaimTypes.EtherPreviousAddress);
            return JsonSerializer.Deserialize<string[]>(claim.Value);
        }

        public static string GetUsername(this ClaimsPrincipal user)
        {
            //TODO
            throw new NotImplementedException();
        }

        public static string? TryGetClientId(this ClaimsPrincipal user)
        {
            if (user is null) return null;

            var claim = user.Claims.FirstOrDefault(claim => claim.Type == DefaultClaimTypes.ClientId);
            return claim?.Value;
        }

        public static string? TryGetEtherAddress(this ClaimsPrincipal user)
        {
            if (user is null) return null;

            var claim = user.Claims.FirstOrDefault(claim => claim.Type == DefaultClaimTypes.EtherAddress);
            return claim?.Value;
        }

        public static string[]? TryGetEtherPrevAddresses(this ClaimsPrincipal user)
        {
            if (user is null) return null;

            var claim = user.Claims.FirstOrDefault(claim => claim.Type == DefaultClaimTypes.EtherPreviousAddress);
            return claim is null ? null : JsonSerializer.Deserialize<string[]>(claim.Value);
        }

#pragma warning disable IDE0060 // Remove unused parameter
        public static string? TryGetUsername(this ClaimsPrincipal user)
        {
            //TODO
            return null;
        }
#pragma warning restore IDE0060 // Remove unused parameter
    }
}
