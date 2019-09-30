import Hapi from '@hapi/hapi';
import Hodor from '.';

const makeRoute = (option = {}) => {
	return {
		method: 'GET',
		path: '/',
		handler() {
			return 'foo';
		},
		...option,
	};
};

const makeServer = async (option = {}) => {
	const server = new Hapi.server();

	await server.register([
		{
			plugin: Hodor,
			options: {
				sessionSecretKey: 'pleasemakethissignificantlymoresecure',
				auth0Domain: 'my-app.auth0.com',
				auth0PublicKey: 'someclientid',
				auth0SecretKey: 'evenmoresecretthanthesessionsecretkey',
			},
		},
	]);

	return server;
};

test('When Hodor is missing response is correct', async () => {
	const server = new Hapi.Server();
	server.route(makeRoute());

	const response = await server.inject('/');

	expect(response.statusCode).toEqual(200);
	expect(response.headers['content-type']).toEqual('text/html; charset=utf-8');
	expect(response.payload).toEqual('foo');
});

test('When the default auth is set response is correct', async () => {
	const server = await makeServer();
	server.route(makeRoute());

	const response = await server.inject('/');

	expect(response.statusCode).toEqual(200);
	expect(response.headers['content-type']).toEqual('text/html; charset=utf-8');
	expect(response.payload).toEqual('foo');
});

test('When request is GET /, it does not redirect without accept header', async () => {
	const server = await makeServer();

	server.route(
		makeRoute({
			config: {
				auth: {
					strategy: 'session',
					mode: 'required',
				},
			},
		}),
	);

	const response = await server.inject('/');

	expect(response.statusCode).toEqual(401);
	expect(response.statusMessage).toEqual('Unauthorized');
	expect(response.headers['content-type']).toEqual(
		'application/json; charset=utf-8',
	);
	expect(Object.keys(response.headers).includes('location')).toBeFalsy();
	expect(JSON.parse(response.payload).message).toEqual(
		'Missing authentication',
	);
});

test('When request is made it honors */* accept header', async () => {
	const server = await makeServer();

	server.route(
		makeRoute({
			config: {
				auth: {
					strategy: 'session',
					mode: 'required',
				},
			},
		}),
	);

	const anyResp = await server.inject({
		url: '/',
		headers: {
			accept: '*/*',
		},
	});

	expect(anyResp.statusCode).toEqual(401);
	expect(anyResp.statusMessage).toEqual('Unauthorized');
	expect(anyResp.headers['content-type']).toEqual(
		'application/json; charset=utf-8',
	);
	expect(Object.keys(anyResp.headers).includes('location')).toBeFalsy();
	expect(JSON.parse(anyResp.payload).message).toEqual('Missing authentication');
});

test('When request is made it honors application/json accept header', async () => {
	const server = await makeServer();
	server.route(
		makeRoute({
			config: {
				auth: {
					strategy: 'session',
					mode: 'required',
				},
			},
		}),
	);

	const jsonPreferred = await server.inject({
		url: '/',
		headers: {
			accept: 'text/html;q=0.9, application/json',
		},
	});

	expect(jsonPreferred.statusCode).toEqual(401);
	expect(jsonPreferred.statusMessage).toEqual('Unauthorized');
	expect(jsonPreferred.headers['content-type']).toEqual(
		'application/json; charset=utf-8',
	);
	expect(Object.keys(jsonPreferred.headers).includes('location')).toBeFalsy();
	expect(JSON.parse(jsonPreferred.payload).message).toEqual(
		'Missing authentication',
	);
});

test('When request is made it honors text/html accept header', async () => {
	const server = await makeServer();
	server.route(
		makeRoute({
			config: {
				auth: {
					strategy: 'session',
					mode: 'required',
				},
			},
		}),
	);

	const htmlResp = await server.inject({
		url: '/',
		headers: {
			accept: 'text/html',
		},
	});

	expect(htmlResp.statusCode).toEqual(302);
	expect(htmlResp.statusMessage).toEqual('Found');
	expect(htmlResp.headers['content-type']).toEqual('text/html; charset=utf-8');
	expect(htmlResp.headers.location).toEqual(
		'/login?next=' + encodeURIComponent('/'),
	);
	expect(htmlResp.payload).toEqual('You are being redirected...');
});

test('When GET /login request is made the response is correct', async () => {
	const server = await makeServer();

	const response = await server.inject('/login');

	expect(response.statusCode).toEqual(302);
	expect(response.statusMessage).toEqual('Found');
	expect(response.headers['set-cookie'].length).toEqual(1);
	expect(response.headers['set-cookie'][0]).toMatch(/^bell-auth0=/);
	expect(response.headers['set-cookie'][0]).toEqual(
		expect.stringContaining('; Max-Age=86400; Expires='),
	);
	expect(response.headers['set-cookie'][0]).toMatch(
		/; HttpOnly; SameSite=Strict; Path=\/$/,
	);
	expect(response.headers.location).toEqual(
		expect.stringContaining(
			'https://my-app.auth0.com/authorize?client_id=someclientid&response_type=code&redirect_uri=http%3A%2F%2F',
		),
	);
	expect(response.headers.location).toEqual(
		expect.stringContaining('%2Flogin&state='),
	);
	expect(response.payload).toEqual('');
});

test('When GET /logout request is made the respones is correct', async () => {
	const server = await makeServer();

	const response = await server.inject('/logout');

	expect(response.statusCode).toEqual(302);
	expect(response.statusMessage).toEqual('Found');
	expect(response.headers['set-cookie'][0]).toEqual(
		'sid=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax',
	);
	expect(response.headers.location).toEqual(
		`https://my-app.auth0.com/v2/logout?returnTo=${encodeURIComponent(
			'https://' + server.info.host + ':' + server.info.port + '/',
		)}`,
	);
	expect(response.payload).toEqual('');
});

test('When GET /logout redirects it goes to next=bah', async () => {
	const server = await makeServer();

	const bare = await server.inject('/logout?next=bah');

	expect(bare.statusCode).toEqual(302);
	expect(bare.statusMessage).toEqual('Found');
	expect(bare.headers.location).toEqual(
		`https://my-app.auth0.com/v2/logout?returnTo=${encodeURIComponent(
			'https://' + server.info.host + ':' + server.info.port + '/bah',
		)}`,
	);
	expect(bare.payload).toEqual('');
});

test('When GET /logout redirects it goes to next=/bah', async () => {
	const server = await makeServer();

	const slash = await server.inject('/logout?next=/bah');

	expect(slash.statusCode).toEqual(302);
	expect(slash.statusMessage).toEqual('Found');
	expect(slash.headers.location).toEqual(
		`https://my-app.auth0.com/v2/logout?returnTo=${encodeURIComponent(
			'https://' + server.info.host + ':' + server.info.port + '/bah',
		)}`,
	);
	expect(slash.payload).toEqual('');
});

test('When GET /logout redirects it goes to next even if encoded', async () => {
	const server = await makeServer();

	const encodedSlash = await server.inject(
		'/logout?next=' + encodeURIComponent('/bah'),
	);

	expect(encodedSlash.statusCode).toEqual(302);
	expect(encodedSlash.statusMessage).toEqual('Found');
	expect(encodedSlash.headers.location).toEqual(
		`https://my-app.auth0.com/v2/logout?returnTo=${encodeURIComponent(
			'https://' + server.info.host + ':' + server.info.port + '/bah',
		)}`,
	);
	expect(encodedSlash.payload).toEqual('');
});

test('When GET /logout rejects absolute urls for next', async () => {
	const server = await makeServer();

	const absolute = await server.inject('/logout?next=http://example.com/bah');

	expect(absolute.statusCode).toEqual(400);
	expect(absolute.statusMessage).toEqual('Bad Request');
	expect(absolute.headers['content-type']).toEqual(
		'application/json; charset=utf-8',
	);
	expect(JSON.parse(absolute.payload).message).toEqual(
		'Absolute URLs are not allowed in the `next` parameter for security reasons',
	);
});

test('When GET /logout rejects absolute urls for next encoded absolute', async () => {
	const server = await makeServer();

	const encodedAbsolute = await server.inject(
		'/logout?next=' + encodeURIComponent('http://example.com/bah'),
	);

	expect(encodedAbsolute.statusCode).toEqual(400);
	expect(encodedAbsolute.statusMessage).toEqual('Bad Request');
	expect(encodedAbsolute.headers['content-type']).toEqual(
		'application/json; charset=utf-8',
	);
	expect(JSON.parse(encodedAbsolute.payload).message).toEqual(
		'Absolute URLs are not allowed in the `next` parameter for security reasons',
	);
});

test('When GET /logout rejects absolute urls for next schemeless', async () => {
	const server = await makeServer();

	const schemeless = await server.inject('/logout?next=//example.com/bah');

	expect(schemeless.statusCode).toEqual(400);
	expect(schemeless.statusMessage).toEqual('Bad Request');
	expect(schemeless.headers['content-type']).toEqual(
		'application/json; charset=utf-8',
	);
	expect(JSON.parse(schemeless.payload).message).toEqual(
		'Absolute URLs are not allowed in the `next` parameter for security reasons',
	);
});

test('When GET /logout rejects absolute urls for next like encoded schemeless', async () => {
	const server = await makeServer();

	const encodedSchemeless = await server.inject(
		'/logout?next=' + encodeURIComponent('//example.com/bah'),
	);

	expect(encodedSchemeless.statusCode).toEqual(400);
	expect(encodedSchemeless.statusMessage).toEqual('Bad Request');
	expect(encodedSchemeless.headers['content-type']).toEqual(
		'application/json; charset=utf-8',
	);
	expect(JSON.parse(encodedSchemeless.payload).message).toEqual(
		'Absolute URLs are not allowed in the `next` parameter for security reasons',
	);
});
