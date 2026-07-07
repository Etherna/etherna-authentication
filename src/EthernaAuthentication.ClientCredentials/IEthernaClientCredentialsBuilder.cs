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

using System;
using System.Collections.Generic;
using System.Net.Http;

namespace Etherna.Authentication.ClientCredentials
{
    /// <summary>
    /// A builder to register client credentials clients against the Etherna SSO server.
    /// </summary>
    public interface IEthernaClientCredentialsBuilder
    {
        /// <summary>
        /// Adds a client credentials client to token management.
        /// </summary>
        /// <param name="tokenClientName">The name identifying the client in token management.</param>
        /// <param name="clientId">The client id, registered on the Etherna SSO server.</param>
        /// <param name="clientSecret">The client secret.</param>
        /// <param name="scopes">The scopes to request with the access token.</param>
        /// <param name="managedHttpClientName">If set, the name of an <see cref="HttpClient"/> to register, attaching the managed access token as bearer.</param>
        /// <param name="configureManagedHttpClient">An optional delegate to configure the managed <see cref="HttpClient"/>.</param>
        /// <returns>A reference to this builder after the operation has completed.</returns>
        IEthernaClientCredentialsBuilder AddClient(
            string tokenClientName,
            string clientId,
            string clientSecret,
            IEnumerable<string> scopes,
            string? managedHttpClientName = null,
            Action<HttpClient>? configureManagedHttpClient = null);
    }
}
