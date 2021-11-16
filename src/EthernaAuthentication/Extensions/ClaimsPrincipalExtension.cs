﻿using System;
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

            return user.Claims.First(claim => claim.Type == ClaimTypes.ClientId).Value;
        }

        public static string GetEtherAddress(this ClaimsPrincipal user)
        {
            if (user is null)
                throw new ArgumentNullException(nameof(user));

            var claim = user.Claims.First(claim => claim.Type == ClaimTypes.EtherAddress);
            return claim.Value;
        }

        public static string[] GetEtherPrevAddresses(this ClaimsPrincipal user)
        {
            if (user is null)
                throw new ArgumentNullException(nameof(user));

            var claim = user.Claims.First(claim => claim.Type == ClaimTypes.EtherPreviousAddresses);
            return JsonSerializer.Deserialize<string[]>(claim.Value) ?? Array.Empty<string>();
        }

        public static string GetUsername(this ClaimsPrincipal user)
        {
            if (user is null)
                throw new ArgumentNullException(nameof(user));

            var claim = user.Claims.First(claim => claim.Type == ClaimTypes.Username);
            return claim.Value;
        }

        public static string? TryGetClientId(this ClaimsPrincipal user)
        {
            if (user is null) return null;

            var claim = user.Claims.FirstOrDefault(claim => claim.Type == ClaimTypes.ClientId);
            return claim?.Value;
        }

        public static string? TryGetEtherAddress(this ClaimsPrincipal user)
        {
            if (user is null) return null;

            var claim = user.Claims.FirstOrDefault(claim => claim.Type == ClaimTypes.EtherAddress);
            return claim?.Value;
        }

        public static string[]? TryGetEtherPrevAddresses(this ClaimsPrincipal user)
        {
            if (user is null) return null;

            var claim = user.Claims.FirstOrDefault(claim => claim.Type == ClaimTypes.EtherPreviousAddresses);
            return claim is null ? null : JsonSerializer.Deserialize<string[]>(claim.Value);
        }

        public static string? TryGetUsername(this ClaimsPrincipal user)
        {
            if (user is null) return null;

            var claim = user.Claims.FirstOrDefault(claim => claim.Type == ClaimTypes.Username);
            return claim?.Value;
        }
    }
}
