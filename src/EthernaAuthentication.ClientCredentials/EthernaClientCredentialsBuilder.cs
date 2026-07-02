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

using Duende.AccessTokenManagement;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Net.Http;

namespace Etherna.Authentication.ClientCredentials
{
    internal sealed class EthernaClientCredentialsBuilder(
        IServiceCollection services,
        Uri tokenEndpoint,
        ClientCredentialsTokenManagementBuilder tokenManagementBuilder)
        : IEthernaClientCredentialsBuilder
    {
        // Methods.
        public IEthernaClientCredentialsBuilder AddClient(
            string tokenClientName,
            string clientId,
            string clientSecret,
            IEnumerable<string> scopes,
            string? managedHttpClientName = null,
            Action<HttpClient>? configureManagedHttpClient = null)
        {
            // Check conditions.
            ArgumentNullException.ThrowIfNull(tokenClientName);
            ArgumentNullException.ThrowIfNull(clientId);
            ArgumentNullException.ThrowIfNull(clientSecret);
            ArgumentNullException.ThrowIfNull(scopes);

            // Register client to token management.
            tokenManagementBuilder.AddClient(tokenClientName, options =>
            {
                options.TokenEndpoint = tokenEndpoint;

                options.ClientId = ClientId.Parse(clientId);
                options.ClientSecret = ClientSecret.Parse(clientSecret);

                options.Scope = Scope.Parse(string.Join(' ', scopes));
            });

            // Register HTTP client that uses the managed access token.
            if (managedHttpClientName is not null)
                services.AddClientCredentialsHttpClient(
                    managedHttpClientName,
                    ClientCredentialsClientName.Parse(tokenClientName),
                    configureManagedHttpClient);

            return this;
        }
    }
}
