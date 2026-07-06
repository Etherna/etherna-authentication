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
using System.ComponentModel;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Etherna.Authentication.Native.CodeFlow
{
    public class SystemBrowserTest
    {
        // Consts.
        private const string StartUrl = "https://sso.etherna.io/connect/authorize?client_id=test&scope=openid";

        // Tests.
        [Fact]
        public async Task InvokeAsyncReturnsCustomSuccessResponseToBrowser()
        {
            var browser = new SystemBrowser(
                customSuccessContentType: "text/plain",
                customSuccessResponse: "Sign in completed.",
                openBrowser: _ => { });

            var invokeTask = browser.InvokeAsync(
                new BrowserOptions(StartUrl, $"http://127.0.0.1:{browser.Port}"),
                CancellationToken.None);

            using var httpClient = new HttpClient();
            var callbackResponse = await httpClient.GetAsync(new Uri($"http://127.0.0.1:{browser.Port}/?code=xyz"));
            await invokeTask;

            Assert.Equal("text/plain", callbackResponse.Content.Headers.ContentType?.MediaType);
            Assert.Equal("Sign in completed.", await callbackResponse.Content.ReadAsStringAsync());
        }

        [Fact]
        public async Task InvokeAsyncReturnsErrorResultWhenBrowserFailsToOpen()
        {
            // Simulate an environment where no browser can be opened, like a headless linux (see EAUTH-17).
            var browser = new SystemBrowser(
                openBrowser: _ => throw new Win32Exception("No such file or directory"));

            var result = await browser.InvokeAsync(
                new BrowserOptions(StartUrl, $"http://127.0.0.1:{browser.Port}"),
                CancellationToken.None);

            Assert.Equal(BrowserResultType.UnknownError, result.ResultType);
            Assert.Contains("Failed to open the system browser", result.Error, StringComparison.Ordinal);
            Assert.Contains("sign in with an API key", result.Error, StringComparison.Ordinal);
        }

        [Fact]
        public async Task InvokeAsyncReturnsSuccessWhenCallbackIsReceived()
        {
            string? openedUrl = null;
            var browser = new SystemBrowser(openBrowser: url => openedUrl = url);

            // The listener is already started when InvokeAsync returns its task.
            var invokeTask = browser.InvokeAsync(
                new BrowserOptions(StartUrl, $"http://127.0.0.1:{browser.Port}"),
                CancellationToken.None);

            //simulate the user completing sign in on the browser
            using var httpClient = new HttpClient();
            var callbackResponse = await httpClient.GetAsync(new Uri($"http://127.0.0.1:{browser.Port}/?code=xyz&state=abc"));
            var result = await invokeTask;

            Assert.Equal(StartUrl, openedUrl);
            Assert.Equal(HttpStatusCode.OK, callbackResponse.StatusCode);
            Assert.Equal(BrowserResultType.Success, result.ResultType);
            Assert.Equal("?code=xyz&state=abc", result.Response);
        }

        [Fact]
        public async Task OpenBrowserOpensUrlWithSystemUrlHandler()
        {
            // Verifiable without a gui only on linux, where the system url handler is xdg-open.
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                return;

            var handlerDir = Directory.CreateTempSubdirectory();
            var capturePath = Path.Combine(handlerDir.FullName, "opened-url");
            var handlerPath = Path.Combine(handlerDir.FullName, "xdg-open");
            await File.WriteAllTextAsync(handlerPath, $"#!/bin/sh\necho \"$1\" > \"{capturePath}\"\n");
            File.SetUnixFileMode(handlerPath, UnixFileMode.UserExecute | UnixFileMode.UserRead | UnixFileMode.UserWrite);

            var originalPath = Environment.GetEnvironmentVariable("PATH");
            try
            {
                //resolve the fake handler before any real one
                Environment.SetEnvironmentVariable("PATH", handlerDir.FullName + Path.PathSeparator + originalPath);

                SystemBrowser.OpenBrowser(StartUrl);

                //the handler process runs detached, wait for it to write the url
                var timeout = DateTime.UtcNow.AddSeconds(10);
                while (!File.Exists(capturePath) && DateTime.UtcNow < timeout)
                    await Task.Delay(50);

                Assert.True(File.Exists(capturePath), "The system url handler has not been invoked.");
                Assert.Equal(StartUrl, (await File.ReadAllTextAsync(capturePath)).Trim());
            }
            finally
            {
                Environment.SetEnvironmentVariable("PATH", originalPath);
                handlerDir.Delete(recursive: true);
            }
        }
    }
}
