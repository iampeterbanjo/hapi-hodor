import Bell from '@hapi/bell';
import Cookie from '@hapi/cookie';

import Accept from '@hapi/accept';
import Joi from '@hapi/joi';
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
		handler: controller.handleLogin,
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
