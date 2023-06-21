# Etherna Authentication

## Overview

Etherna user authentication clients for different .Net projects.

### Packages

Etherna Authentication offers different NuGet packages with different scopes:

* **Etherna.Authentication** offers common constants, abstract classes and interfaces to use with other packages.  
Doesn't offer any default client registration method, or authentication flow.

* **Etherna.Authentication.AspNetCore** implements authentication client with code flow for Asp.Net projects.  
It provides support to registration with extension on Asp.Net `AuthenticationBuilder`.

* **Etherna.Authentication.NativeAsp** implement authentication client with code flow for native applications, using a local Asp.Net return page.  
It provides management of user's access tokens, and is the recomended library to implement user authentication with native applications.

* **Etherna.Authentication.NativeScript** implements managed authentication client with password flow for native scripted application.  
Password flow is necessary to implement authentication with Etherna's API keys, and it is required by applications with scripted user authentication.  
Because password flow is generally considered less secure than code flow, use this package only if *Etherna.Authentication.NativeAsp* is not an option.

## Issue reports

If you've discovered a bug, or have an idea for a new feature, please report it to our issue manager based on Jira https://etherna.atlassian.net/projects/EAUTH.

## Questions? Problems?

For questions or problems please write an email to [info@etherna.io](mailto:info@etherna.io).
