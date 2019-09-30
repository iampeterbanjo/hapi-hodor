import Bell from '@hapi/bell';
import Cookie from '@hapi/cookie';

import Path from 'path';
import Boom from '@hapi/boom';
import Accept from '@hapi/accept';
import Joi from '@hapi/joi';
import { hasHost } from 'url-type';
import { vars } from './utils';
import Controller from './controller';
const defaultParams = request => {
	const { screen = '' } = request.query || {};
	const lastScreen = Array.isArray(screen) ? screen[screen.length - 1] : screen;
	return lastScreen ? { screen: lastScreen } : {};
};

const redirectTo = ({ headers }) => {
	const [favoriteType] = Accept.mediaTypes(headers.accept);
	return ['text/html', 'text/*'].includes(favoriteType) && '/login';
};

const register = async (server, option) => {
	const config = Joi.attempt(
		option,
		Joi.object()
			.required()
			.keys({
				forceHttps: Joi.boolean()
					.optional()
					.default(false),
				isSecure: Joi.boolean()
					.optional()
					.default(false),
				isHttpOnly: Joi.boolean()
					.optional()
					.default(true),
				validateFunc: Joi.function().optional(),
				providerParams: Joi.function()
					.optional()
					.default(defaultParams),
				sessionSecretKey: Joi.string()
					.required()
					.min(32),
				auth0Domain: Joi.string()
					.required()
					.hostname()
					.min(3),
				auth0PublicKey: Joi.string()
					.required()
					.token()
					.min(10),
				auth0SecretKey: Joi.string()
					.required()
					.min(30)
					.regex(/^[A-Za-z\d_-]+$/u),
			}),
	);

	await server.register([Cookie, Bell]);

	server.auth.strategy('session', 'cookie', {
		validateFunc: config.validateFunc,
		cookie: {
			name: 'sid',
			password: config.sessionSecretKey,
			clearInvalid: true,
			isHttpOnly: config.isHttpOnly,
			isSecure: config.isSecure,
			isSameSite: 'Lax',
		},
		redirectTo,
		appendNext: true,
	});

	server.auth.strategy('auth0', 'bell', {
		provider: 'auth0',
		config: {
			domain: config.auth0Domain,
		},
		ttl: 1000 * 60 * 60 * 24,
		password: config.sessionSecretKey,
		clientId: config.auth0PublicKey,
		clientSecret: config.auth0SecretKey,
		isHttpOnly: config.isHttpOnly,
		isSecure: config.isSecure,
		forceHttps: config.forceHttps,
		providerParams: config.providerParams,
	});

	const resolveNext = query => {
		const { next } = query;
		const lastNext = Array.isArray(next) ? next[next.length - 1] : next;
		if (hasHost(lastNext)) {
			throw Boom.badRequest(
				'Absolute URLs are not allowed in the `next` parameter for security reasons',
			);
		}
		return Path.posix.resolve('/', lastNext || '');
	};

	const controller = new Controller(config);

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
		handler(request, h) {
			const { auth } = request;
			if (auth.isAuthenticated) {
				// Credentials also have: .expiresIn, .token, .refreshToken
				// Put the Auth0 profile in a cookie. The browser may ignore it If it is too big.
				request.cookieAuth.set({ user: auth.credentials.profile });
				return h.redirect(resolveNext(auth.credentials.query));
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

	server.route({
		method: 'GET',
		path: '/logout',
		config: {
			description: 'End a user session',
			tags: ['user', 'auth', 'session', 'logout'],
			auth: false,
		},
		handler: controller.handleLogout,
	});
};

export default {
	register,
	name: vars.name,
	version: vars.version,
	dependencies: ['@hapi/cookie', '@hapi/bell'],
};
