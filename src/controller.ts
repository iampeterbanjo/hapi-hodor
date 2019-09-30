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

	handleLogout = (request, h) => {
		const { auth0Domain } = this.config;

		request.cookieAuth.clear();
		const returnTo = encodeURIComponent(
			'https://' + request.info.host + this.resolveNext(request.query),
		);
		return h.redirect(`https://${auth0Domain}/v2/logout?returnTo=${returnTo}`);
	};
}
