# Etherna Authentication

Etherna Authentication is a set of **.NET client libraries** (NuGet packages) to authenticate users and applications against the Etherna SSO server — it is a library solution, not a runnable application. Four packages: `Etherna.Authentication` (common constants, abstractions, and the OpenID Connect client base), `Etherna.Authentication.AspNetCore` (code-flow authentication for ASP.NET Core applications), `Etherna.Authentication.ClientCredentials` (client credentials flow for applications and services, without user interaction), and `Etherna.Authentication.Native` (sign-in services and user token management for native .NET applications, with code and api-key/password flows).

## Build, run, test

Projects multi-target **net9.0 and net10.0**. There is no `Directory.Build.props`: every `.csproj` carries its own full property block — `TreatWarningsAsErrors=true`, `AnalysisMode=AllEnabledByDefault`, `Nullable=enable`, `EnableNETAnalyzers=true`, `IsAotCompatible=true` — warnings break the build. When adding a project, copy the property block from an existing one.

```bash
dotnet restore EthernaAuthentication.sln
dotnet build EthernaAuthentication.sln -c Release    # compiles both target frameworks
```

There is no test project and nothing to run: `dotnet build` (warnings-as-errors on every target framework) is the verification step. Because the libraries compile against the lowest target (`net9.0`), do not use APIs introduced only in net10.0 — it would pass on `net10.0` and fail the build on `net9.0`.

Versioning is automatic via **GitVersion** (`GitVersion.MsBuild` in every project, plus SourceLink). CI (`.github/workflows/`): pushes to `dev` and `release/**` build, test, pack and push unstable packages to MyGet; tags `v*.*.*` push stable packages to NuGet.

## Architecture

Solution `EthernaAuthentication.sln`, four library projects. Project folders are named `EthernaAuthentication*`, root namespaces use `Etherna.Authentication[.<Module>]`; under the root, the namespace mirrors the folder path.

- **`src/EthernaAuthentication`** (`Etherna.Authentication`) — Core constants and abstractions shared by the other packages; offers no client registration by itself. Holds the Etherna constants (`EthernaDefaults`, `EthernaClaimTypes`, `EthernaScopes` — kept in sync with the SSO server), the OIDC client contract and base (`IEthernaOpenIdConnectClient`, `EthernaOpenIdConnectClientBase`, reading typed values from user claims via `Get…Async`/`TryGet…Async` pairs), `IDiscoveryDocumentService`/`DiscoveryDocumentService`, and `ClaimJsonSerializerContext` (source-generated JSON for AOT). Depends on `IdentityModel` only.
- **`src/EthernaAuthentication.AspNetCore`** (`Etherna.Authentication.AspNetCore`) — Code-flow client for ASP.NET Core applications. Registration via the `AddEthernaOpenIdConnect` overloads on `AuthenticationBuilder`; its `EthernaOpenIdConnectClient` reads claims from the current `HttpContext` and is registered **scoped** because of its user claims cache.
- **`src/EthernaAuthentication.ClientCredentials`** (`Etherna.Authentication.ClientCredentials`) — Client credentials (machine-to-machine) flow for applications and services, built on `Duende.AccessTokenManagement` (base package, no ASP.NET dependency — usable from console apps too). Registration via `AddEthernaClientCredentials` on `IServiceCollection`, which returns an `IEthernaClientCredentialsBuilder` to register named token clients, each optionally paired with a managed `HttpClient` attaching the access token as bearer. The token endpoint is built by convention (`{ssoBaseUrl}/connect/token`) without network discovery, so the SSO server is not required to be reachable at startup.
- **`src/EthernaAuthentication.Native`** (`Etherna.Authentication.Native`) — Client for native .NET applications, with user token management built on `Duende.AccessTokenManagement.OpenIdConnect` (`LocalUserTokenStore`, `LocalUserAccessTokenRetriever`). Two sign-in flows, both implementing `IEthernaSignInService`: `CodeFlow/` (`EthernaCodeSignInService` + `SystemBrowser`/`LoopbackHttpListener` — opens the system browser and receives the SSO redirect on a local listener) and `PasswordFlow/` (`EthernaApiKeySignInService` — api-key authentication without user interaction). Registration via `AddEthernaCodeOidcClient` / `AddEthernaApiKeyOidcClient` on `IServiceCollection`.

Key cross-cutting points:

- **This is a library: always `ConfigureAwait(false)`** on every await (`CA2007` is enforced by the analyzers). This is the opposite of the Etherna ASP.NET Core service repos (beehive, credit, gateway, index, sso), where `ConfigureAwait` is omitted.
- **Public API surface is the product.** These packages are published to NuGet and consumed by the other Etherna repos (e.g. `EthernaSdk` builds its user clients on `Etherna.Authentication.Native`): keep the public surface intentional, and remember both target frameworks must compile.
- **Native AOT / trim compatible** (`IsAotCompatible=true` everywhere): keep new code AOT-safe — JSON serialization goes through the source-generated `ClaimJsonSerializerContext`, no reflection-based serialization.
- Assemblies declare `[CLSCompliant(false)]` in `Properties/AssemblyInfo.cs`.

## Issue tracker

Bugs and features are tracked in Jira project **EAUTH** (https://etherna.atlassian.net/projects/EAUTH). Branch names follow `feature/EAUTH-<id>-<slug>` / `improve/EAUTH-<id>-<slug>` / `fix/EAUTH-<id>-<slug>` — match this when creating branches. `dev` is the integration branch, `main` is stable; stable releases are tagged `v<version>`.

# Coding Style

## General Principles

- Keep commits clean: only include changes strictly necessary for the task at hand.
- Keep `README.md` aligned: when a change touches packages, features, or build steps, update `README.md` in the same change.
- Never reference AI agents or assistants in commits or code — no agent names, no `Co-Authored-By` agent trailers, no "generated/assisted by" notes. Commit messages and code must read as the team's own work.
- Exceptions to these conventions are accepted when strictly necessary or when they significantly improve code quality. Justify with a comment where needed.
- All elements (usings, properties, methods, fields, enum members, etc.) are always alphabetically ordered within their respective sections.
- Prefer primary constructors whenever possible — not limited to DI services. A parameter needing a light transformation still qualifies: capture it and derive a field. Fall back to a classic constructor only when the body needs real logic that can't be expressed as a field initializer.
- Keep code clean: remove unused variables, dead code, and redundant imports.
- Don't extract a private helper method for logic used in a single place — inline it. Reserve helpers for code shared by two or more call sites (or when extraction materially clarifies an otherwise long, complex method).
- Every source file starts with the standard LGPL-3.0 copyright header (`// Copyright 2021-present Etherna SA` … see any existing file).

## Naming

- **Classes/Structs**: PascalCase (`EthernaOpenIdConnectClient`, `LoopbackHttpListener`)
- **Interfaces**: `I` prefix (`IEthernaSignInService`, `IDiscoveryDocumentService`)
- **Async methods**: always `Async` suffix (`GetDiscoveryDocumentAsync`, `SignInAsync`)
- **Properties**: PascalCase (`IsAuthenticated`, `CurrentUser`)
- **Private fields**: `_camelCase` only when backing a same-named property; otherwise plain `camelCase`
- **Primary constructor parameters**: `camelCase` without underscore
- **Constants**: PascalCase (`DefaultFailureContentType`, `DefaultTimeout`); underscore only to disambiguate variants of the same concept (`Role_Dotnet`, `Role_IdentityModel`) — `CA1707` is disabled to allow these
- **Enums**: PascalCase type and members
- **Namespaces**: `Etherna.Authentication.<Module>` (e.g. `Etherna.Authentication.AspNetCore`, `Etherna.Authentication.Native`)
- **Options classes**: `Options` suffix (`EthernaCodeSignInServiceOptions`)

## Code Organization

- One class per file, filename matches class name
- Namespace mirrors folder structure exactly (under the `Etherna.Authentication` root namespace)
- Block-scoped namespaces: `namespace X { ... }` — NOT file-scoped
- Using directives at the top of the file, before the namespace block, always alphabetically ordered and kept to the minimum necessary
- No global usings — each file declares its own imports
- Module-based organization: `AspNetCore/`, `Native/`, `CodeFlow/`, `PasswordFlow/`

## Comments

Principal comments (generally multiline, important):
```csharp
// Capital start, ending period.
// Continued on next line if needed.
```

Secondary/separator comments:
```csharp
//no space, no capital, no ending period
```

Comment only what helps a future reader: non-obvious behavior, intent, or a gotcha. Do **not** write narration of your own reasoning or decisions — that belongs in the commit message / PR description, never in committed code. If the code and section comments already make the intent clear, add nothing.

XML doc comments (`///`) document the public API where they aid understanding (see `AuthenticationBuilderExtensions`); they are not compiler-enforced.

## Member Ordering Within a Class

Use principal-style section comments to delimit groups (singular `// Constructor.` when there is only one), in this order:

```csharp
// Consts.
// Fields.
// Constructors.
// Properties.
// Methods.
// Static methods.
// Protected methods.
// Helpers.
```

## Class Design

- `sealed` for concrete implementations (`LoopbackHttpListener`)
- `abstract` for flow base classes
- Primary constructors everywhere the constructor is a simple assignment:
  ```csharp
  public class EthernaOpenIdConnectClient(
      IDiscoveryDocumentService discoveryDocumentService,
      IEthernaSignInService ethernaSignInService,
      IUserTokenManagementService userTokenManagementService)
      : EthernaOpenIdConnectClientBase(discoveryDocumentService)
  {
  }
  ```
- Protected override pattern for hook methods
- Try-pattern methods return nullable: `Task<string?> TryGetUserIdAsync()`

## Async Patterns

- Always suffix with `Async`
- `CancellationToken cancellationToken = default` as the optional last parameter for new code (non-nullable, `default` — not `CancellationToken? = null`); implementations of the Duende interfaces keep the interface's `ct` parameter name
- Return `Task` or `Task<T>`, never `async void`
- **Always use `ConfigureAwait(false)`** — this is a library
- `Task.CompletedTask` for no-op implementations
- `TaskCompletionSource<T>` for async coordination

## Null Handling

- Nullable reference types enabled (`<Nullable>enable</Nullable>`)
- `ArgumentNullException.ThrowIfNull(param)` for parameter validation
- `is null` / `is not null` (not `== null`)
- Prefer `null` over `default` as default value for optional parameters
- `??` and `??=` operators; `??` with throw: `httpContext ?? throw new InvalidOperationException()`
- `ClaimsPrincipal?` for potentially unauthenticated contexts

## Formatting

- Allman braces (opening brace on new line)
- 4-space indentation (2 spaces in `.csproj` files, per `.editorconfig`)
- Expression-bodied members for simple delegations
- LINQ method chains: one operation per line, aligned
- Blank line between member sections

## C# Language Features

- Pattern matching: `is`, `is not`, type patterns, property patterns
- Prefer a property pattern over a chain of `&&` that combines a type/null check with member accesses: it expresses the condition as a single declarative "shape" the value must match
- Switch expressions for multi-branch returns
- Primary constructors everywhere applicable
- Collection expressions: `[]`, `[..spread]`
- Prefer collection expressions over constructors to initialize any collection: `[]` not `new()`, `["a", "b"]` not `new List<string> { "a", "b" }`. Use a constructor only when a collection expression can't express the intent (e.g. presizing capacity with `new List<T>(capacity)`).
- Target-typed `new()` when type is clear from context (for non-collection types)

## LINQ

- Method syntax preferred over query syntax
- Query syntax only for complex join/groupby with multiple `from` clauses
- Fluent chaining, one operation per line for readability

## Dependency Injection

- Constructor injection exclusively
- Extension methods for registration: on `AuthenticationBuilder` (`AddEthernaOpenIdConnect`) and on `IServiceCollection` (`AddEthernaCodeOidcClient`, `AddEthernaApiKeyOidcClient`)
- `AddSingleton` for the native sign-in services, token store, and discovery document service; `AddScoped` for the ASP.NET Core `EthernaOpenIdConnectClient` (user claims cache); `AddTransient` for `LocalUserAccessTokenRetriever`
- `IOptions<T>` for configuration
- `IHttpClientFactory` for HTTP clients
