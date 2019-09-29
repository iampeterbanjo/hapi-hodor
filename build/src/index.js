"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const bell_1 = __importDefault(require("@hapi/bell"));
const cookie_1 = __importDefault(require("@hapi/cookie"));
const path_1 = __importDefault(require("path"));
const boom_1 = __importDefault(require("@hapi/boom"));
const accept_1 = __importDefault(require("@hapi/accept"));
const joi_1 = __importDefault(require("@hapi/joi"));
const url_type_1 = require("url-type");
const package_json_1 = require("../package.json");
const defaultParams = request => {
    const { screen = '' } = request.query || {};
    const lastScreen = Array.isArray(screen) ? screen[screen.length - 1] : screen;
    return lastScreen ? { screen: lastScreen } : {};
};
const redirectTo = ({ headers }) => {
    const [favoriteType] = accept_1.default.mediaTypes(headers.accept);
    return ['text/html', 'text/*'].includes(favoriteType) && '/login';
};
const register = async (server, option) => {
    const config = joi_1.default.attempt(option, joi_1.default.object()
        .required()
        .keys({
        forceHttps: joi_1.default.boolean()
            .optional()
            .default(false),
        isSecure: joi_1.default.boolean()
            .optional()
            .default(false),
        isHttpOnly: joi_1.default.boolean()
            .optional()
            .default(true),
        validateFunc: joi_1.default.function().optional(),
        providerParams: joi_1.default.function()
            .optional()
            .default(defaultParams),
        sessionSecretKey: joi_1.default.string()
            .required()
            .min(32),
        auth0Domain: joi_1.default.string()
            .required()
            .hostname()
            .min(3),
        auth0PublicKey: joi_1.default.string()
            .required()
            .token()
            .min(10),
        auth0SecretKey: joi_1.default.string()
            .required()
            .min(30)
            .regex(/^[A-Za-z\d_-]+$/u),
    }));
    await server.register([cookie_1.default, bell_1.default]);
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
        if (url_type_1.hasHost(lastNext)) {
            throw boom_1.default.badRequest('Absolute URLs are not allowed in the `next` parameter for security reasons');
        }
        return path_1.default.posix.resolve('/', lastNext || '');
    };
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
            throw boom_1.default.unauthorized(auth.error.message);
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
        handler(request, h) {
            request.cookieAuth.clear();
            const returnTo = encodeURIComponent('https://' + request.info.host + resolveNext(request.query));
            return h.redirect(`https://${config.auth0Domain}/v2/logout?returnTo=${returnTo}`);
        },
    });
};
exports.default = {
    register,
    name: package_json_1.name,
    version: package_json_1.version,
    dependencies: ['@hapi/cookie', '@hapi/bell'],
};
//# sourceMappingURL=index.js.map