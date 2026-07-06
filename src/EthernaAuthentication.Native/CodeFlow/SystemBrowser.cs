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

using Duende.IdentityModel.OidcClient.Browser;
using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace Etherna.Authentication.Native.CodeFlow
{
    internal sealed class SystemBrowser : IBrowser
    {
        // Fields.
        private readonly string? customFailureContentType;
        private readonly string? customFailureResponse;
        private readonly string? customSuccessContentType;
        private readonly string? customSuccessResponse;
        private readonly string path;

        // Constructor.
        public SystemBrowser(
            int? port = null,
            string? path = null,
            string? customFailureContentType = null,
            string? customFailureResponse = null,
            string? customSuccessContentType = null,
            string? customSuccessResponse = null)
        {
            this.customFailureContentType = customFailureContentType;
            this.customFailureResponse = customFailureResponse;
            this.customSuccessContentType = customSuccessContentType;
            this.customSuccessResponse = customSuccessResponse;
            this.path = path ?? string.Empty;
            if (!port.HasValue)
                Port = GetRandomUnusedPort();
            else
                Port = port.Value;
        }

        // Properties.
        public int Port { get; }

        // Methods.
        public async Task<BrowserResult> InvokeAsync(BrowserOptions options, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(options);

            using var listener = new LoopbackHttpListener(
                Port,
                path,
                customFailureContentType,
                customFailureResponse,
                customSuccessContentType,
                customSuccessResponse);

            OpenBrowser(options.StartUrl);

#pragma warning disable CA1031 // Do not catch general exception types
            try
            {
                var result = await listener.WaitForCallbackAsync().ConfigureAwait(false);
                if (string.IsNullOrWhiteSpace(result))
                    return new BrowserResult { ResultType = BrowserResultType.UnknownError, Error = "Empty response." };

                return new BrowserResult { Response = result, ResultType = BrowserResultType.Success };
            }
            catch (TaskCanceledException ex)
            {
                return new BrowserResult { ResultType = BrowserResultType.Timeout, Error = ex.Message };
            }
            catch (Exception ex)
            {
                return new BrowserResult { ResultType = BrowserResultType.UnknownError, Error = ex.Message };
            }
#pragma warning restore CA1031 // Do not catch general exception types
        }

        // Static methods.
        public static void OpenBrowser(string? url)
        {
            url ??= string.Empty;
            try
            {
                Process.Start(url);
            }
            catch
            {
                // hack because of this: https://github.com/dotnet/corefx/issues/10361
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    url = url.Replace("&", "^&", StringComparison.InvariantCultureIgnoreCase);
                    Process.Start(new ProcessStartInfo("cmd", $"/c start {url}") { CreateNoWindow = true });
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                    Process.Start("xdg-open", url);
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                    Process.Start("open", url);
                else
                    throw;
            }
        }

        // Helpers.
        private static int GetRandomUnusedPort()
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();

#if NET8_0_OR_GREATER
            listener.Dispose();
#endif
            return port;
        }
    }
}
