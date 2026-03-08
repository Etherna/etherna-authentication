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

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;
using System;

namespace Etherna.Authentication.AspNetCore
{
    /// <summary>
    /// Extension methods to configure Etherna OpenId Connect client.
    /// </summary>
    public static class EthernaAuthenticationOptionsExtensions
    {
        /// <summary>
        /// Adds Etherna OpenIdConnect-based authentication to <see cref="AuthenticationBuilder"/> using the default scheme.
        /// The default scheme is specified by <see cref="EthernaDefaults.AuthenticationScheme"/>.
        /// <para>
        /// Etherna authentication allows application users to sign in with their Etherna account.
        /// </para>
        /// </summary>
        /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
        /// <param name="configureOptions">A delegate to configure <see cref="OpenIdConnectOptions"/>.</param>
        /// <returns>A reference to <paramref name="builder"/> after the operation has completed.</returns>
        public static AuthenticationBuilder AddEthernaOpenIdConnect(this AuthenticationBuilder builder, Action<OpenIdConnectOptions> configureOptions)
            => builder.AddEthernaOpenIdConnect(EthernaDefaults.AuthenticationScheme, configureOptions);

        /// <summary>
        /// Adds Etherna OpenIdConnect-based authentication to <see cref="AuthenticationBuilder"/> using the default scheme.
        /// The default scheme is specified by <see cref="EthernaDefaults.AuthenticationScheme"/>.
        /// <para>
        /// Etherna authentication allows application users to sign in with their Etherna account.
        /// </para>
        /// </summary>
        /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
        /// <param name="authenticationScheme">The authentication scheme.</param>
        /// <param name="configureOptions">A delegate to configure <see cref="OpenIdConnectOptions"/>.</param>
        /// <returns>A reference to <paramref name="builder"/> after the operation has completed.</returns>
        public static AuthenticationBuilder AddEthernaOpenIdConnect(this AuthenticationBuilder builder, string authenticationScheme, Action<OpenIdConnectOptions> configureOptions)
            => builder.AddEthernaOpenIdConnect(authenticationScheme, EthernaDefaults.DisplayName, configureOptions);

        /// <summary>
        /// Adds Etherna OpenIdConnect-based authentication to <see cref="AuthenticationBuilder"/> using the default scheme.
        /// The default scheme is specified by <see cref="EthernaDefaults.AuthenticationScheme"/>.
        /// <para>
        /// Etherna authentication allows application users to sign in with their Etherna account.
        /// </para>
        /// </summary>
        /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
        /// <param name="authenticationScheme">The authentication scheme.</param>
        /// <param name="displayName">A display name for the authentication handler.</param>
        /// <param name="configureOptions">A delegate to configure <see cref="OpenIdConnectOptions"/>.</param>
        public static AuthenticationBuilder AddEthernaOpenIdConnect(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<OpenIdConnectOptions> configureOptions)
        {
            // Check conditions.
            ArgumentNullException.ThrowIfNull(builder, nameof(builder));
            ArgumentNullException.ThrowIfNull(configureOptions, nameof(configureOptions));

            var options = new OpenIdConnectOptions();
            configureOptions(options);

            if (options.Authority is null)
                throw new InvalidOperationException("Authority can't be null");

            // Add Etherna oidc client.
            builder.Services.AddSingleton<IDiscoveryDocumentService>(
                new DiscoveryDocumentService(options.Authority, options.RequireHttpsMetadata));
            builder.Services.AddScoped<IEthernaOpenIdConnectClient, EthernaOpenIdConnectClient>(); //scoped because of user claims cache

            builder.AddOpenIdConnect(authenticationScheme, displayName, configureOptions);

            return builder;
        }
    }
}
