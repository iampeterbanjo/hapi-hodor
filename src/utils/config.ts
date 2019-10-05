import Joi from '@hapi/joi';

const defaultParams = request => {
	const { screen = '' } = request.query || {};
	const lastScreen = Array.isArray(screen) ? screen[screen.length - 1] : screen;
	return lastScreen ? { screen: lastScreen } : {};
};

const configSchema = Joi.object()
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
		auth0Audience: Joi.string()
			.required()
			.uri(),
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
	});

export const getConfig = option => Joi.attempt(option, configSchema);
