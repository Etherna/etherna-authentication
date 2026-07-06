# Etherna Authentication

[![Etherna.Authentication on NuGet](https://img.shields.io/nuget/v/Etherna.Authentication?label=Etherna.Authentication)](https://www.nuget.org/packages/Etherna.Authentication/)
[![Etherna.Authentication.AspNetCore on NuGet](https://img.shields.io/nuget/v/Etherna.Authentication.AspNetCore?label=Etherna.Authentication.AspNetCore)](https://www.nuget.org/packages/Etherna.Authentication.AspNetCore/)
[![Etherna.Authentication.ClientCredentials on NuGet](https://img.shields.io/nuget/v/Etherna.Authentication.ClientCredentials?label=Etherna.Authentication.ClientCredentials)](https://www.nuget.org/packages/Etherna.Authentication.ClientCredentials/)
[![Etherna.Authentication.Native on NuGet](https://img.shields.io/nuget/v/Etherna.Authentication.Native?label=Etherna.Authentication.Native)](https://www.nuget.org/packages/Etherna.Authentication.Native/)
[![Target frameworks](https://img.shields.io/badge/.NET-9%20%7C%2010-512BD4)](#supported-frameworks)
[![License: LGPL-3.0](https://img.shields.io/badge/license-LGPL--3.0-blue)](COPYING-LESSER)

**Etherna Authentication** provides the .NET client libraries to authenticate users and services against
the [Etherna SSO](https://github.com/Etherna/etherna-sso) server. Built on OpenID Connect and
[Duende.AccessTokenManagement](https://github.com/DuendeSoftware/foss), it covers interactive user sign-in
for web and native applications, api-key scripted automation, and machine-to-machine authentication —
always with automatic access token acquisition, caching and refresh.

Etherna Authentication is a set of **libraries**, not an application. Add the package matching your
application type to sign in with an Etherna account and call the Etherna APIs with managed tokens.

## Contents

- [Features](#features)
- [Packages](#packages)
- [Installation](#installation)
- [Usage examples](#usage-examples)
  - [ASP.NET Core web app — sign in users with Etherna](#aspnet-core-web-app--sign-in-users-with-etherna)
  - [Read the authenticated user's identity](#read-the-authenticated-users-identity)
  - [Service-to-service — client credentials](#service-to-service--client-credentials)
  - [Native app — interactive sign-in with the system browser](#native-app--interactive-sign-in-with-the-system-browser)
  - [Native app — scripted sign-in with an api key](#native-app--scripted-sign-in-with-an-api-key)
  - [Etherna constants — schemes, scopes and claims](#etherna-constants--schemes-scopes-and-claims)
- [Supported frameworks](#supported-frameworks)
- [Building and testing](#building-and-testing)
- [Project layout](#project-layout)
- [Package repositories](#package-repositories)
- [Contributing](#contributing)
- [Issue reports](#issue-reports)
- [Questions? Problems?](#questions-problems)
- [License](#license)

## Features

- **Etherna sign-in for ASP.NET Core** — plug the Etherna OpenID Connect code flow into the standard
  `AuthenticationBuilder` with a single extension method.
- **Interactive sign-in for native apps** — open the system browser, let the user authenticate on the SSO,
  and receive the result on a local loopback listener. The recommended flow for desktop and console apps.
- **Api-key sign-in for automation** — authenticate a user without interaction (password flow), for
  scripted scenarios where opening a browser is not an option.
- **Client credentials for services** — authenticate an application with its own identity, without any
  user. No ASP.NET dependency, usable by any kind of .NET application or service.
- **Automatic token management** — access tokens are acquired, cached and refreshed transparently,
  powered by Duende.AccessTokenManagement.
- **Managed `HttpClient`s** — register named `HttpClient` instances that attach a valid bearer token to
  every request automatically; consume them through the standard `IHttpClientFactory`.
- **Typed identity access** — `IEthernaOpenIdConnectClient` exposes the authenticated identity (user id,
  username, Ethereum address and previous addresses, roles, scopes) as strongly-typed async getters.
- **Etherna constants** — authentication scheme, scope and claim-type constants shared by all Etherna
  services (`EthernaDefaults`, `EthernaScopes`, `EthernaClaimTypes`).

## Packages

Four NuGet packages are published, one per application type plus a common core:

| Package | Use it for | Depends on |
| --- | --- | --- |
| [**Etherna.Authentication**](https://www.nuget.org/packages/Etherna.Authentication/) | Common constants, abstractions and the OIDC client base. No client registration methods or authentication flows on its own. | — |
| [**Etherna.Authentication.AspNetCore**](https://www.nuget.org/packages/Etherna.Authentication.AspNetCore/) | ASP.NET Core web apps signing in users with the code flow, with automatic user access token management. | `Etherna.Authentication` |
| [**Etherna.Authentication.ClientCredentials**](https://www.nuget.org/packages/Etherna.Authentication.ClientCredentials/) | Applications and services authenticating with their own identity (client credentials flow), without user interaction. | — |
| [**Etherna.Authentication.Native**](https://www.nuget.org/packages/Etherna.Authentication.Native/) | Native local apps (desktop, console) signing in users with the interactive code flow or an api key (password flow). | `Etherna.Authentication` |

## Installation

```bash
# ASP.NET Core web apps:
dotnet add package Etherna.Authentication.AspNetCore

# Services authenticating with their own identity:
dotnet add package Etherna.Authentication.ClientCredentials

# Native/console apps signing in users:
dotnet add package Etherna.Authentication.Native
```

`Etherna.Authentication` is brought in transitively where needed; add it directly only if you just need
the shared constants and abstractions.

## Usage examples

### ASP.NET Core web app — sign in users with Etherna

Register the Etherna OpenID Connect client on the standard authentication builder. User access token
management is registered automatically and bound to the scheme: set `SaveTokens = true` to consume managed
user tokens, and request the `offline_access` scope to permit token refresh.

```csharp
using Etherna.Authentication;
using Etherna.Authentication.AspNetCore;
using Microsoft.AspNetCore.Authentication.Cookies;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(options =>
    {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = EthernaDefaults.AuthenticationScheme;
    })
    .AddCookie()
    .AddEthernaOpenIdConnect(options =>
    {
        options.Authority = "https://sso.etherna.io/";
        options.ClientId = builder.Configuration["SsoServer:Clients:Webapp:ClientId"]!;
        options.ClientSecret = builder.Configuration["SsoServer:Clients:Webapp:Secret"]!;

        options.ResponseType = "code";
        options.SaveTokens = true;              // consume managed user tokens

        options.Scope.Add(EthernaScopes.EtherAccounts);
        options.Scope.Add(EthernaScopes.Role);
        options.Scope.Add("offline_access");    // permit user access token refresh
    });

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();
```

The client id and secret must match a client registered on the Etherna SSO server. Once signed in, call
downstream APIs on the user's behalf with Duende's user token management (e.g.
`HttpContext.GetUserAccessTokenAsync()` or a user-token `HttpClient`) — see the
[Duende.AccessTokenManagement docs](https://docs.duendesoftware.com/accesstokenmanagement/).

### Read the authenticated user's identity

`IEthernaOpenIdConnectClient` is registered by every flow and exposes the authenticated identity as typed
getters. The `Get*` methods throw if the claim is missing; the `TryGet*` variants return `null` instead.

```csharp
using Etherna.Authentication;

public class AccountController(IEthernaOpenIdConnectClient oidcClient) : Controller
{
    public async Task<IActionResult> MeAsync()
    {
        var userId = await oidcClient.GetUserIdAsync();
        var username = await oidcClient.GetUsernameAsync();
        var etherAddress = await oidcClient.GetEtherAddressAsync();
        var roles = await oidcClient.TryGetRolesAsync() ?? [];
        var canUseGateway = await oidcClient.HasScopesAsync(EthernaScopes.UserApiGateway);

        // ...
    }
}
```

### Service-to-service — client credentials

Authenticate an application with its own identity, without any user interaction. The registration doesn't
depend on ASP.NET and doesn't require the SSO server to be reachable at startup. Registering a *managed*
`HttpClient` is the simplest way to consume the token: every request sent through it carries a valid
bearer token, acquired and refreshed automatically.

```csharp
using Etherna.Authentication;
using Etherna.Authentication.ClientCredentials;

var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddEthernaClientCredentials(new Uri("https://sso.etherna.io/"))
    .AddClient(
        tokenClientName: "ethernaSso",
        clientId: "yourServiceClientId",
        clientSecret: "yourServiceClientSecret",
        scopes: [EthernaScopes.EthernaSsoUserContactInfo],
        managedHttpClientName: "ssoApi",
        configureManagedHttpClient: client =>
            client.BaseAddress = new Uri("https://sso.etherna.io/"));

var host = builder.Build();

// Anywhere in the app: resolve the managed HttpClient by name.
// A valid access token is attached to each request automatically.
var httpClientFactory = host.Services.GetRequiredService<IHttpClientFactory>();
var httpClient = httpClientFactory.CreateClient("ssoApi");

var response = await httpClient.GetAsync(new Uri("api/v0.3/...", UriKind.Relative));
```

`AddClient` can be chained to register several clients, each with its own scopes and managed `HttpClient`.

### Native app — interactive sign-in with the system browser

The recommended flow for desktop and console apps. `SignInAsync` opens the system browser on the Etherna
SSO login page and receives the authentication result on a local loopback listener, on the given port.
The `offline_access` and `ether_accounts` scopes are always requested; pass any additional scope you need.

```csharp
using Etherna.Authentication;
using Etherna.Authentication.Native;
using Microsoft.Extensions.DependencyInjection;

var services = new ServiceCollection();

services.AddEthernaCodeOidcClient(
    authority: "https://sso.etherna.io/",
    clientId: "yourClientId",
    clientSecret: null,                       // public native clients have no secret
    returnUrlPort: 11420,                     // must match the client's redirect url on the SSO server
    scopes: [EthernaScopes.UserApiGateway],
    managedHttpClientName: "ethernaApi");

await using var serviceProvider = services.BuildServiceProvider();

// Open the system browser and wait for the user to complete the sign-in.
var signInService = serviceProvider.GetRequiredService<IEthernaSignInService>();
await signInService.SignInAsync();

// Read the signed-in user's identity.
var oidcClient = serviceProvider.GetRequiredService<IEthernaOpenIdConnectClient>();
Console.WriteLine($"Signed in as {await oidcClient.GetUsernameAsync()}");

// Call Etherna APIs: tokens are attached and refreshed automatically.
var httpClient = serviceProvider.GetRequiredService<IHttpClientFactory>().CreateClient("ethernaApi");
```

### Native app — scripted sign-in with an api key

For automation scenarios where no user can interact with a browser, sign in with an Etherna api key
(password flow). The registration mirrors the code flow one; only the sign-in step changes, requiring no
interaction. Prefer the interactive code flow whenever scripting is not a requirement — the password flow
is generally considered less secure.

```csharp
using Etherna.Authentication;
using Etherna.Authentication.Native;
using Microsoft.Extensions.DependencyInjection;

var services = new ServiceCollection();

services.AddEthernaApiKeyOidcClient(
    authority: "https://sso.etherna.io/",
    apiKey: Environment.GetEnvironmentVariable("ETHERNA_API_KEY")!,
    scopes: [EthernaScopes.UserApiGateway],
    managedHttpClientName: "ethernaApi");

await using var serviceProvider = services.BuildServiceProvider();

// Signs in with the api key, without opening any browser.
var signInService = serviceProvider.GetRequiredService<IEthernaSignInService>();
await signInService.SignInAsync();

var httpClient = serviceProvider.GetRequiredService<IHttpClientFactory>().CreateClient("ethernaApi");
```

### Etherna constants — schemes, scopes and claims

The core package ships the constants shared by all Etherna services:

- **`EthernaDefaults`** — the `Etherna` authentication scheme and display name.
- **`EthernaScopes`** — standard OIDC scopes (`openid`, `profile`), Etherna identity scopes
  (`ether_accounts`, `role`), user-facing API scopes (`userApi.credit`, `userApi.gateway`,
  `userApi.index`, `userApi.sso`) and service-to-service scopes for admin-created clients.
- **`EthernaClaimTypes`** — claim names issued by the SSO server (`ether_address`,
  `ether_prev_addresses`, `preferred_username`, roles, scopes, …), useful with authorization policies:

```csharp
using Etherna.Authentication;

services.AddAuthorization(options =>
{
    options.AddPolicy("RequireEtherAddress", policy =>
        policy.RequireClaim(EthernaClaimTypes.EtherAddress));
});
```

## Supported frameworks

The libraries multi-target **.NET 9 and 10**. Install them into any project on a compatible framework.

## Building and testing

Etherna Authentication builds with the standard .NET SDK:

```bash
dotnet restore EthernaAuthentication.sln
dotnet build   EthernaAuthentication.sln -c Release   # compiles every target framework
dotnet test    EthernaAuthentication.sln -c Release   # runs the xUnit test project
```

`TreatWarningsAsErrors=true` and `AnalysisMode=AllEnabledByDefault` are enabled across the solution, so
warnings break the build on every target framework.

Coding conventions and architecture notes live in [AGENTS.md](AGENTS.md).

## Project layout

```
src/
  EthernaAuthentication                    core: constants, abstractions, OIDC client base, discovery service
  EthernaAuthentication.AspNetCore         code-flow user authentication for ASP.NET Core (→ core)
  EthernaAuthentication.ClientCredentials  client credentials flow for services, no ASP.NET dependency
  EthernaAuthentication.Native             code and api-key flows for native local apps (→ core)
test/
  EthernaAuthentication.UnitTest           xUnit + Moq unit tests
```

## Package repositories

You can get the latest public releases from the [NuGet.org feed](https://www.nuget.org/profiles/etherna).

If you'd like to work with the latest internal releases, you can use our
[custom MyGet feed](https://www.myget.org/F/etherna/api/v3/index.json) (NuGet V3).

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) and our
[Code of Conduct](CODE_OF_CONDUCT.md) before opening a pull request.

## Issue reports

If you've discovered a bug, or have an idea for a new feature, please report it to our issue manager
based on Jira: https://etherna.atlassian.net/projects/EAUTH.

Detailed reports with stack traces, actual and expected behaviours are welcome.

## Questions? Problems?

For questions or problems please write an email to [info@etherna.io](mailto:info@etherna.io).

## License

![LGPL Logo](https://www.gnu.org/graphics/lgplv3-with-text-154x68.png)

We use the GNU Lesser General Public License v3 (LGPL-3.0) for this project.
If you require a custom license, you can contact us at [license@etherna.io](mailto:license@etherna.io).
