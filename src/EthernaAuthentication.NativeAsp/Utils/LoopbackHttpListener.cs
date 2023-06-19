using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using System;
using System.Threading.Tasks;

namespace Etherna.Authentication.NativeAsp.Utils
{
    internal sealed class LoopbackHttpListener : IDisposable
    {
        // Consts.
        private const string DefaultFailureContentType = "text/html";
        private const string DefaultFailureResponse = "<h1>Invalid request.</h1>";
        private const string DefaultSuccessContentType = "text/html";
        private const string DefaultSuccessResponse = "<h1>You can now return to the application.</h1>";
        private const int DefaultTimeout = 60 * 5; // 5 mins (in seconds)

        // Fields.
        private bool isDisposed;

        private readonly IWebHost host;
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
            if (path.StartsWith("/", StringComparison.InvariantCultureIgnoreCase))
                path = path[1..];

            _url = $"http://127.0.0.1:{port}/{path}";

            host = new WebHostBuilder()
                .UseKestrel()
                .UseUrls(_url)
                .Configure(Configure)
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
