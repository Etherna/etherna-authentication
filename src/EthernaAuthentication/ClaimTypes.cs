namespace Etherna.Authentication
{
    public static class ClaimTypes
    {
        public const string ClientId = "client_id";
        public const string EtherAddress = "ether_address";
        public const string EtherPreviousAddresses = "ether_prev_addresses";
        public const string IsWeb3Account = "isWeb3Account";
        public const string Role = System.Security.Claims.ClaimTypes.Role;
        public const string Username = "preferred_username";
    }
}
