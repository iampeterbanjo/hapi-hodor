import Authority from './authority';
import casual from 'casual';

const domain = 'test.eu.auth0.com';
const options = {
	cache: true,
	rateLimit: true,
	jwksRequestsPerMinute: 5,
	jwksUri: `https://${domain}/.well-known/jwks.json`,
};

const kid = casual.uuid;
const azp = casual.uuid;
const decoded = {
	header: {
		kid,
		typ: 'JWT',
		alg: 'RS256',
	},
	payload: {
		azp,
		iss: `https://${domain}/`,
		sub: `${azp}@clients`,
		aud: casual.url,
		iat: 1570289133,
		exp: 1570375533,
		gty: 'client-credentials',
	},
	signature: casual.uuid,
};

describe('Given options and JwksRsa', () => {
	test('When new Authority is created Jwks is called with options', () => {
		const JwksRsa = jest.fn();
		new Authority({ JwksRsa, options });

		expect(JwksRsa).toBeCalledWith(options);
	});

	test('When authority.getKey is called with decoded data, JwksRsa.getSigningKey is called with decoded.header.kid', () => {
		const getSigningKey = jest.fn();
		const JwksRsa = jest.fn().mockImplementation(() => ({
			getSigningKey,
		}));
		const authority = new Authority({ JwksRsa, options });

		authority.getKey(decoded);

		expect(getSigningKey).toBeCalledWith(decoded.header.kid);
	});
});
