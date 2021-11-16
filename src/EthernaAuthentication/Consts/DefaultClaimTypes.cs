using System.Collections.Generic;
using System.Security.Claims;

namespace Etherna.Authentication.Consts
{
    public static class DefaultClaimTypes
    {
        public const string ClientId = "client_id";
        public const string EtherAddress = "ether_address";
        public const string EtherPreviousAddresses = "ether_prev_addresses";
        public const string IsWeb3Account = "isWeb3Account";
        public const string Role = ClaimTypes.Role;
        public const string Username = "preferred_username";

        public static readonly IEnumerable<string> CustomClaimNames =
            new[] { EtherAddress, EtherPreviousAddresses, IsWeb3Account, Role, Username };
    }
}
