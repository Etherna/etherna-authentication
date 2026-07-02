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

namespace Etherna.Authentication.ClientCredentials
{
    /// <summary>
    /// Extension methods to configure Etherna client credentials clients.
    /// </summary>
    public static class ServiceCollectionExtensions
    {
        /// <summary>
        /// Adds Etherna client credentials token management to <see cref="IServiceCollection"/>.
        /// <para>
        /// Client credentials authentication allows applications and services to authenticate against
        /// the Etherna SSO server with their own identity, without any user interaction.
        /// Register clients with <see cref="IEthernaClientCredentialsBuilder.AddClient"/> on the returned builder.
        /// </para>
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection"/>.</param>
        /// <param name="ssoBaseUrl">The Etherna SSO server base url.</param>
        /// <param name="requireHttps">Require HTTPS on the SSO base url. Loopback addresses are always exempted.</param>
        /// <returns>A builder to register client credentials clients.</returns>
        public static IEthernaClientCredentialsBuilder AddEthernaClientCredentials(
            this IServiceCollection services,
            Uri ssoBaseUrl,
            bool requireHttps = true)
        {
            // Check conditions.
            ArgumentNullException.ThrowIfNull(services);
            ArgumentNullException.ThrowIfNull(ssoBaseUrl);
            if (requireHttps &&
                ssoBaseUrl.Scheme != Uri.UriSchemeHttps &&
                !ssoBaseUrl.IsLoopback)
                throw new ArgumentException("HTTPS is required for the SSO base URL.", nameof(ssoBaseUrl));

            // Register client token management. It also registers the required HybridCache to keep tokens.
            var tokenManagementBuilder = services.AddClientCredentialsTokenManagement();

            // Build token endpoint from IdentityServer's conventional route, without network discovery.
            // This way the SSO server is not required to be reachable when the application starts.
            var tokenEndpoint = new Uri(ssoBaseUrl.AbsoluteUri.TrimEnd('/') + "/connect/token");

            return new EthernaClientCredentialsBuilder(services, tokenEndpoint, tokenManagementBuilder);
        }
    }
}
