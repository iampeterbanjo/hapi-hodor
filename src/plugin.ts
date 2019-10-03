import Bell from '@hapi/bell';
import Cookie from '@hapi/cookie';
import Accept from '@hapi/accept';

import { vars, getConfig, time } from './utils';
import Controller from './controller';

const redirectTo = ({ headers }) => {
	const [favoriteType] = Accept.mediaTypes(headers.accept);

	return ['text/html', 'text/*'].includes(favoriteType) && '/login';
};

const register = async (server, option) => {
	const config = getConfig(option);

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
		ttl: time.oneDay,
		password: config.sessionSecretKey,
		clientId: config.auth0PublicKey,
		clientSecret: config.auth0SecretKey,
		isHttpOnly: config.isHttpOnly,
		isSecure: config.isSecure,
		forceHttps: config.forceHttps,
		providerParams: config.providerParams,
	});

	const controller = new Controller(config);

	controller.handleLogin(server);
	controller.handleLogout(server);
};

export default {
	register,
	name: vars.name,
	version: vars.version,
};
