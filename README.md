# hapi-hodor

![test coverage][test-coverage]

> [Auth0] authentication for [Hapi][hapi]

## Why

- Based on [hapi-doorkeeper][hapi-doorkeeper] because I wanted authentication on localhost without HTTPS.

## Usage

Register the plugin on your server to add the `/login` and `/logout` routes, as well as the `session` strategy so that you can protect your app's routes with authentication.

```js
const Hapi = require('@hapi/hapi');
const Hodor = require('hapi-hodor');

const server = new Hapi.server();

const init = async () => {
  await server.register({
    plugin: Hodor,
    options: {
      sessionSecretKey: process.env.SESSION_SECRET_KEY,
      auth0Domain: process.env.AUTH0_DOMAIN,
      auth0PublicKey: process.env.AUTH0_PUBLIC_KEY,
      auth0SecretKey: process.env.AUTH0_SECRET_KEY,
    },
  });
  server.route({
    method: 'GET',
    path: '/dashboard',
    config: {
      auth: {
        strategy: 'session',
        mode: 'required',
      },
    },
    handler(request) {
      const { user } = request.auth.credentials;
      return `Hi ${
        user.name
      }, you are logged in! Here is the profile from Auth0: <pre>${JSON.stringify(
        user.raw,
        null,
        4,
      )}</pre> <a href="/logout">Click here to log out</a>`;
    },
  });
  await server.start();
  console.log('Server ready:', server.info.uri);
};

init();
```

When using a JWT Bearer token in your request header setup your routes like below. Note that the auth strategy, validate function ONLY checks for the existence of a `user_id` which will be set by Auth0.

```JavaScript
server.route({
  method: 'GET',
  path: '/api/private',
  config: {
    auth: 'jwt',
  },
  handler: (request, reply) => {
    // if you want to validate the existence of a user
    const { user } = request.auth.credentials;
    if(!user) throw Boom.unauthorized();

    return {
      message: 'So secure.',
    };
  },
});
```

In the example above, only logged in users are able to access `/dashboard`, as denoted by the `session` strategy being `required`. If you are logged in, it will display your profile, otherwise it will redirect you to a login screen and after you log in it will redirect you back to `/dashboard`.

Authentication is managed by [Auth0](https://auth0.com/). A few steps are required to finish the integration.

1. [Sign up for Auth0](https://auth0.com/)
2. [Set up an Auth0 Application](https://auth0.com/docs/applications/application-types)
3. [Provide credentials from Auth0](#plugin-options)

After users log in, a session cookie is created for them so that the server remembers them on future requests. The cookie is stateless, encrypted, and secured using flags such as `HttpOnly`. The user's [Auth0 profile](https://auth0.com/docs/user-profile/normalized/oidc) is automatically retrieved and stored in the session when they log in. You can access the profile data at `request.auth.credentials.user`. See [@hapi/cookie](https://github.com/hapijs/hapi-auth-cookie) and [iron](https://github.com/hueniverse/iron) for details about the cookie implementation and security.

APIs can also be protected by the `session` strategy. Clients can send an [Accept](https://tools.ietf.org/html/rfc7231#section-5.3.2) header with a value of `application/json` to indicate that they would prefer a JSON error instead of a redirect to the login page for users who are not logged in. The client can use this to show an error message or redirect the user manually, as appropriate.

## API

### Routes

Standard user authentication routes are added to your server when the plugin is registered.

#### GET /login

Tags: `user`, `auth`, `session`, `login`

Begins a user session. If a session is already active, the user will be given the opportunity to log in with a different account.

If users deny access to a [social](https://auth0.com/docs/identityproviders) account, they will be redirected back to the login page so that they may try again, because they probably clicked the wrong account or provider by accident. Other login errors will be returned to the client with a 401 Unauthorized status.

After logging in, users are redirected to the URL specified in the `next` query parameter, which defaults to `/`, the root of the server.

As an example, the login button on your FAQ page might look be written as `<a href="/login?next=/faq">Log in</a>`.

Only relative URLs are allowed in `next` for security reasons.

Routes that use the `session` strategy to require login have the `next` parameter set automatically for them, so that users are always sent back to the correct place.

#### GET /logout

Tags: `user`, `auth`, `session`, `logout`

Ends a user session. Safe to visit regardless of whether a session is active or the validity of the user's credentials. After logging out, users will be redirected to the URL specified in the `next` query parameter, which defaults to `/` (see [`/login`](#get-login) for details).

### Plugin options

#### sessionSecretKey

Type: `string`

A passphrase used to secure session cookies. Should be at least 32 characters long and occasionally rotated. See [Iron](https://github.com/hueniverse/iron) for details.

#### auth0Domain

Type: `string`

The domain used to log in to Auth0. This should be the domain of your tenant (e.g. `my-company.auth0.com`) or your own [custom domain](https://auth0.com/docs/custom-domains) (e.g. `auth.my-company.com`).

#### auth0PublicKey

Type: `string`

The ID of your [Auth0 Application](https://manage.auth0.com/#/applications), sometimes referred to as the Client ID.

#### auth0SecretKey

Type: `string`

The secret key of your [Auth0 Application](https://manage.auth0.com/#/applications), sometimes referred to as the Client Secret.

#### providerParams(request)

Type: `function`

An optional event handler where you can decide which query parameters to send to Auth0. Should return an object of key/value pairs that will be serialized to a query string. See the [`providerParams` option](https://github.com/hapijs/bell/blob/master/API.md#options) in [bell](https://github.com/hapijs/bell) for details.

By default, we forward any `screen` parameter passed to `/login`, so that you can implement "Log In" and "Sign Up" buttons that go to the correct screen. To set this up, modify your [Hosted Login Page](https://auth0.com/docs/hosted-pages/login#how-to-customize-your-login-page) and set Lock's [`initialScreen`](https://auth0.com/docs/libraries/lock/v11/configuration#initialscreen-string-) option to use the value of `config.extraParams.screen`. After that, visiting `/login?screen=signUp` will show the Sign Up screen instead of the Log In screen.

#### validateFunc(request, session)

Type: `function`

An optional event handler where you can put business logic to check and modify the session on each request. See the [`validateFunc` option](https://github.com/hapijs/hapi-auth-cookie#hapi-auth-cookie) in [hapi-auth-cookie](https://github.com/hapijs/hapi-auth-cookie) for details.

This is a good place to set [authorization scopes for users](https://futurestud.io/tutorials/hapi-restrict-user-access-with-scopes), if you need to restrict access to some routes for certain users.

## Related

- [lock](https://github.com/auth0/lock) - UI widget used on the login page

## Contributing

See our [contributing guidelines](https://github.com/sholladay/hapi-doorkeeper/blob/master/CONTRIBUTING.md 'Guidelines for participating in this project') for more details.

1. Fork it.
2. Make a feature branch: `git checkout -b my-new-feature`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin my-new-feature`
5. Submit a pull request.

[hapi-doorkeeper]: https://github.com/sholladay/hapi-doorkeeper
[hapi]: https://hapijs.com
[auth0]: https://auth0.com
[test-coverage]: ./badges/coverage.svg
