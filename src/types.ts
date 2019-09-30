export type Config = {
	sessionSecretKey: string;
	auth0Domain: string;
	auth0PublicKey: string;
	auth0SecretKey: string;
	forceHttps: boolean;
	isSecure: boolean;
	isHttpOnly: boolean;
	providerParams: object;
};
