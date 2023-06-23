//   Copyright 2021-present Etherna Sagl
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

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
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            if (configureOptions is null)
                throw new ArgumentNullException(nameof(configureOptions));

            var options = new OpenIdConnectOptions();
            configureOptions(options);

            if (options.Authority is null)
                throw new InvalidOperationException("Authority can't be null");

            // Add Etherna oidc client.
            builder.Services.AddSingleton<IDiscoveryDocumentService>(
                new DiscoveryDocumentService(options.Authority, options.RequireHttpsMetadata));
            builder.Services.AddScoped<IEthernaOpenIdConnectClient, EthernaOpenIdConnectClient>();

            builder.AddOpenIdConnect(authenticationScheme, displayName, configureOptions);

            return builder;
        }
    }
}
