// Copyright 2021-present Etherna SA
// This file is part of EthernaAuthentication.
//
// EthernaAuthentication is free software: you can redistribute it and/or modify it under the terms of the
// GNU Lesser General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// EthernaAuthentication is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License along with EthernaAuthentication.
// If not, see <https://www.gnu.org/licenses/>.

using System.Security.Claims;
using System.Threading.Tasks;

namespace Etherna.Authentication.Native
{
    /// <summary>
    /// Sign in a user with any of the registered native authentication flows.
    /// The flow is selected at sign-in time, choosing the <c>SignInAsync</c> overload.
    /// </summary>
    public interface IEthernaSignInService
    {
        // Properties.
        /// <summary>
        /// The authentication scheme name of the flow used by the current sign-in,
        /// or <c>null</c> if no user is signed in.
        /// </summary>
        string? CurrentAuthenticationSchemeName { get; }

        /// <summary>
        /// The currently signed-in user, or <c>null</c> if no user is signed in.
        /// </summary>
        ClaimsPrincipal? CurrentUser { get; }

        /// <summary>
        /// Whether a user is currently signed in.
        /// </summary>
        bool IsAuthenticated { get; }

        // Methods.
        /// <summary>
        /// Sign in interactively with the code flow, opening the system browser.
        /// </summary>
        Task SignInAsync();

        /// <summary>
        /// Sign in with an Etherna api key (password flow), without user interaction.
        /// </summary>
        /// <param name="apiKey">The Etherna api key</param>
        Task SignInAsync(string apiKey);
    }
}
