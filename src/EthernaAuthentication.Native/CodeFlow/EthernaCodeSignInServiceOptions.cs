namespace Etherna.Authentication.Native.CodeFlow
{
    public class EthernaCodeSignInServiceOptions
    {
        public string AuthenticationSchemeName { get; set; } = EthernaDefaults.AuthenticationScheme;
        public int ReturnUrlPort { get; set; }
    }
}
