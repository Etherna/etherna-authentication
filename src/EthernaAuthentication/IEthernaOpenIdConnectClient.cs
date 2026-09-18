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

using System.Threading.Tasks;

namespace Etherna.Authentication
{
    public interface IEthernaOpenIdConnectClient
    {
        Task<string> GetClientIdAsync();
        Task<string> GetEtherAddressAsync();
        Task<string[]> GetEtherPrevAddressesAsync();
        Task<string[]> GetRolesAsync();
        Task<string> GetUserIdAsync();
        Task<string> GetUsernameAsync();
        Task<bool> HasScopesAsync(params string[] scopes);

        /// <summary>
        /// Asks the userinfo endpoint whether it still accepts the user access token
        /// </summary>
        /// <returns>
        /// True if the endpoint answered 401: the token isn't valid anymore, e.g. because its user was
        /// deleted after the issuance. False in any other case, also when the endpoint can't be asked
        /// (principal without a subject, no access token) or fails in a different way
        /// </returns>
        Task<bool> IsUserTokenRejectedAsync();

        Task<string?> TryGetClientIdAsync();
        Task<string?> TryGetEtherAddressAsync();
        Task<string[]?> TryGetEtherPrevAddressesAsync();
        Task<string[]?> TryGetRolesAsync();
        Task<string?> TryGetUserIdAsync();
        Task<string?> TryGetUsernameAsync();
    }
}