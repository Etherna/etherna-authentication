# Etherna Authentication

## Overview

Etherna user authentication clients for different .Net projects.

### Packages

Etherna Authentication offers different NuGet packages with different scopes:

* **Etherna.Authentication** offers common constants, abstract classes and interfaces to use with other packages.  
Doesn't offer any default client registration method, or authentication flow.

* **Etherna.Authentication.AspNetCore** implements authentication client with code flow for Asp.Net projects.  
It provides support to registration with extension on Asp.Net `AuthenticationBuilder`.

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
