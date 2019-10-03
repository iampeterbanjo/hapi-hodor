import Boom from '@hapi/boom';
import Path from 'path';
import { hasHost } from 'url-type';
import { Config } from './types';

export default class Controller {
	config: Config;

	constructor(config: Config) {
		this.config = config;
	}

	resolveNext = (query: { [key: string]: string }) => {
		const { next } = query;
		const lastNext = Array.isArray(next) ? next[next.length - 1] : next;
		if (hasHost(lastNext)) {
			throw Boom.badRequest(
				'Absolute URLs are not allowed in the `next` parameter for security reasons',
			);
		}
		return Path.posix.resolve('/', lastNext || '');
	};

	handleLogout = server => {
		server.route({
			method: 'GET',
			path: '/logout',
			config: {
				description: 'End a user session',
				tags: ['user', 'auth', 'session', 'logout'],
				auth: false,
			},
			handler: (request, h) => {
				const { auth0Domain } = this.config;

				request.cookieAuth.clear();
				const returnTo = encodeURIComponent(
					'https://' + request.info.host + this.resolveNext(request.query),
				);

				return h.redirect(
					`https://${auth0Domain}/v2/logout?returnTo=${returnTo}`,
				);
			},
		});
	};

	handleLogin = server => {
		server.route({
			method: 'GET',
			path: '/login',
			config: {
				description: 'Begin a user session',
				tags: ['user', 'auth', 'session', 'login'],
				auth: {
					strategy: 'auth0',
					mode: 'try',
				},
			},

			handler: (request, h) => {
				const { auth } = request;

				if (auth.isAuthenticated) {
					// Credentials also have: .expiresIn, .token, .refreshToken
					// Put the Auth0 profile in a cookie. The browser may ignore it If it is too big.
					request.cookieAuth.set({ user: auth.credentials.profile });
					return h.redirect(this.resolveNext(auth.credentials.query));
				}
				// This happens when users deny us access to their OAuth provider.
				// Chances are they clicked the wrong social icon.
				if (auth.error.message.startsWith('App rejected')) {
					// Give the user another chance to login.
					return h.redirect('/login');
				}

				throw Boom.unauthorized(auth.error.message);
			},
		});
	};
}
