import { DecodedToken } from 'jwks-rsa';

export default class Authority {
	client;

	constructor({ JwksRsa, options }) {
		this.client = JwksRsa(options);
	}

	public getKey = (decoded: DecodedToken) => {
		return this.client.getSigningKey(decoded.header.kid);
	};
}
