import Authority from './authority';
import { options, decoded } from '../fixtures';

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
