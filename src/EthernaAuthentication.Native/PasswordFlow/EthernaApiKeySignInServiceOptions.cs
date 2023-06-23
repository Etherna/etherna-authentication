namespace Etherna.Authentication.Native.PasswordFlow
{
    public class EthernaApiKeySignInServiceOptions
    {
        public string? ApiKey { get; set; }
        public string AuthenticationSchemeName { get; set; } = EthernaDefaults.AuthenticationScheme;
    }
}
