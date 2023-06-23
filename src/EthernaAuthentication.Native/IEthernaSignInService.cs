using System.Security.Claims;
using System.Threading.Tasks;

namespace Etherna.Authentication.Native
{
    public interface IEthernaSignInService
    {
        // Properties.
        ClaimsPrincipal? CurrentUser { get; }
        bool IsAuthenticated { get; }

        // Methods.
        Task SignInAsync();
    }
}
