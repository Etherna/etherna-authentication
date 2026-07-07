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

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using System;
using System.Threading.Tasks;

namespace Etherna.Authentication.Native.CodeFlow
{
    internal sealed class LoopbackHttpListener : IDisposable
    {
        // Consts.
        private const string DefaultFailureContentType = "text/html; charset=utf-8";
        private const string DefaultFailureResponse = DefaultReturnPages.Failure;
        private const string DefaultSuccessContentType = "text/html; charset=utf-8";
        private const string DefaultSuccessResponse = DefaultReturnPages.Success;
        private const int DefaultTimeout = 60 * 5; // 5 mins (in seconds)

        // Fields.
        private bool isDisposed;

        private readonly IHost host;
        private readonly TaskCompletionSource<string> _source = new();
        private readonly string _url;
        private readonly string failureContentType;
        private readonly string failureResponse;
        private readonly string successContentType;
        private readonly string successResponse;

        // Constructor and dispose.
        public LoopbackHttpListener(
            int port,
            string? path = null,
            string? failureContentType = null,
            string? failureResponse = null,
            string? successContentType = null,
            string? successResponse = null)
        {
            this.failureContentType = failureContentType ?? DefaultFailureContentType;
            this.failureResponse = failureResponse ?? DefaultFailureResponse;
            this.successContentType = successContentType ?? DefaultSuccessContentType;
            this.successResponse = successResponse ?? DefaultSuccessResponse;

            path ??= string.Empty;
            if (path.StartsWith('/'))
                path = path[1..];

            _url = $"http://127.0.0.1:{port}/{path}";

            host = new HostBuilder()
                .ConfigureWebHost(webHostBuilder =>
                {
                    webHostBuilder
                        .UseKestrel()
                        .UseUrls(_url)
                        .Configure(Configure);
                })
                .Build();
            host.Start();
        }

        public void Dispose()
        {
            Task.Run(async () =>
            {
                await Task.Delay(500).ConfigureAwait(false);
                Dispose(true);
                GC.SuppressFinalize(this);
            });
        }

        private void Dispose(bool disposing)
        {
            if (isDisposed)
                return;

            if (disposing)
                host.Dispose();

            isDisposed = true;
        }

        // Properties.
        public string Url => _url;

        // Methods.
        public Task<string> WaitForCallbackAsync(int timeoutInSeconds = DefaultTimeout)
        {
            Task.Run(async () =>
            {
                await Task.Delay(timeoutInSeconds * 1000).ConfigureAwait(false);
                _source.TrySetCanceled();
            });

            return _source.Task;
        }

        // Helpers.
        private void Configure(IApplicationBuilder app)
        {
            app.Run(async ctx =>
            {
                if (ctx.Request.Method == "GET")
                    await SetResultAsync(ctx.Request.QueryString.Value ?? "", ctx).ConfigureAwait(false);
                else
                    ctx.Response.StatusCode = 405;
            });
        }

        private async Task SetResultAsync(string value, HttpContext ctx)
        {
            _source.TrySetResult(value);

#pragma warning disable CA1031 // Do not catch general exception types
            try
            {
                ctx.Response.StatusCode = 200;
                ctx.Response.ContentType = successContentType;
                await ctx.Response.WriteAsync(successResponse).ConfigureAwait(false);
                await ctx.Response.Body.FlushAsync().ConfigureAwait(false);
            }
            catch
            {
                ctx.Response.StatusCode = 400;
                ctx.Response.ContentType = failureContentType;
                await ctx.Response.WriteAsync(failureResponse).ConfigureAwait(false);
                await ctx.Response.Body.FlushAsync().ConfigureAwait(false); ;
            }
#pragma warning restore CA1031 // Do not catch general exception types
        }
    }
}
