# Etherna Authentication

## Overview

Etherna user authentication clients for different .Net projects.

### Packages

Etherna Authentication offers different NuGet packages with different scopes:

* **Etherna.Authentication** offers common constants, abstract classes and interfaces to use with other packages.  
Doesn't offer any default client registration method, or authentication flow.

* **Etherna.Authentication.AspNetCore** implements authentication client with code flow for Asp.Net projects.  
It provides support to registration with extension on Asp.Net `AuthenticationBuilder`.

* **Etherna.Authentication.ClientCredentials** implements authentication with client credentials flow for .Net applications and services.  
It permits to authenticate an application with its own identity, without any user interaction, and to consume `HttpClient` instances with automatic access token management. It doesn't depend on Asp.Net, so it can be used by any kind of application.

* **Etherna.Authentication.Native** implement authentication client for native local applications.  
It provides management of user's access tokens, and offers two different authentication flows:
  * *Code flow*: is the recomended flow to implement user authentication with native applications.  
    It creates a local Asp.Net return page, and receives the authentication output from sso redirection.
  * *Password flow*: is used with api key user authentication. It permits to authenticate an user without its direct interaction.  
    It is required by applications with scripted user authentication, but it is generally considered less secure than code flow.  
    Use api key aythentication only if code flow is not an option, because of scripting automation requirements.

## Issue reports

If you've discovered a bug, or have an idea for a new feature, please report it to our issue manager based on Jira https://etherna.atlassian.net/projects/EAUTH.

## Questions? Problems?

For questions or problems please write an email to [info@etherna.io](mailto:info@etherna.io).

## License

![LGPL Logo](https://www.gnu.org/graphics/lgplv3-with-text-154x68.png)

We use the GNU Lesser General Public License v3 (LGPL-3.0) for this project.
If you require a custom license, you can contact us at [license@etherna.io](mailto:license@etherna.io).
