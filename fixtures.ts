import casual from 'casual';

const domain = 'test.eu.auth0.com';
const azp = casual.uuid;

export const options = {
	cache: true,
	rateLimit: true,
	jwksRequestsPerMinute: 5,
	jwksUri: `https://${domain}/.well-known/jwks.json`,
};

export const kid = casual.uuid;

export const decoded = {
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

// openssl genrsa -out private_key.pem 2048
export const PRIVATE_KEY = `
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAox1vvOi+i854DZUcmAvdVs6wvDTOrZe4OBciU4jwOFyXh9g2
EONXA2z3KLU28PJyd8rjimMtCOpmzFjDJseSHf2SpQz8CS1Dlfnrfk6LmWwsBWAw
VrHLryGWyMXsG/HGSX61O8ENo3pTDaA6/zvcXIpPAmccVocuH/f+Cd79YauOaBzQ
HF7M57UEnZvX3s4O0P0co0q2nNuP0WUooqy5qY7fSKOd9d5Pkp0h+qAyKTVukQFF
IeKrKgnvA8PDOr3ljk5fapwnJl84HIP9OSGC8zzUE51bJIqUjb3cvk5jUHUM1NQV
DoBvSpvboxRc6+Kf0zsjXUTTSpus2kBeAM+sKQIDAQABAoIBAGhOBonSeyaDnRly
ZJqF28AK49E2I4O2JUMY6AZq5tHjw7JGfCxIc/fo0hPh7YQeRTx9LQvtZ3rwCVRa
3lAKBlHPONr6dqCXpUReUEywhWxSU8QMQlztzMXswLMafWVRMe8Fa3cOeF41dq6b
654S9VLnzqZGsURTpRckSfqd8YFmYYznjbuKlotVE62yMG4He9P8hXxEECi0OINl
pimnYyKiXJ6DVxhQtc/hpP12haNyCl0w0tKtGGg1FvBAA06BfWOMS/Mpw+jOA20P
6M7zckY7W/2SfFzEGP0wJRTGWe6y6RAmBtuntX4DyBjxeUjAxUrUrUmLktwcsZMx
9YBUPUECgYEAzWI/TsVutIM5xC4jtxuB8UVHWdAw5iY/a74wUCDmtUluHh423b+V
ZzdGBiGynjv8RHCx+VpIjRHGNGRNdaoJADuGDf99FmcNAnyomKj3de+Y6BgDQNVb
+2kO+iSdSPM3A11IVi6aAXc2B82l3uC2dVG2eh+HqN7ik7ANkm4YFI0CgYEAy1Bu
ukcHcSB1S7UMFxXi6eT9zy8DjUnLdosw4LiekzUEMflvFjL2gGivT9lxs1Zd5yfw
Mmt1ygH+4LuE8SOBC+YpNCx1/AkgPVOy5Lqa+sBcuwjtlWPskMdiqQCvxFk0m1J1
vHhCAJ4ZMCSKdMs3BuIFuSir0JO/2zlgBOgnZQ0CgYBQ7CsBgGz0FthF4eAUn3P9
ekx4qLz7kYpfi1pB2BTOzRXkLAd2K6xUNMUUWWalTgFBfh3Bn78CRkSQFA0pFUvi
mZFiJo5Eq2nG1xMew0RtZXAb0opFm0tYrbZG/PIz8hB09OYxfr8TYMMbI/386RE6
/G0nhRDQirE/e5h9X3+BaQKBgH90QLXN6UBl1KJNMPMX6VQvFV1YX6Wm6UG7KDz3
/5DQ33xkndsQv67n8V7hNYHzVpKeWtmAvCqS7bD8XO6+DxvigVoPtTb2kZtgaPky
cg1XocouYqIQLjDkjVjc8VLpiS0FmIE58kZo1el0PsfQzQInluboNC1hMhi/8w2g
a3HRAoGBAJFWm4Q+OWcLMkdAzwRrCNEGmq1N863xD5nih0WCi3InYKBQu9nHvWTR
jJEurs6qYHgvg7PkkhspiMbXydWCS+UmT3ajNwOPiGFeEO9lHCQ/Hcb3NjeoW8ku
ddVW99q4eLD9cY6xRajm8vzhxWsrEBgFZBATis9Qe7rR4umO94pR
-----END RSA PRIVATE KEY-----
`;

// openssl rsa -pubout -in private_key.pem -out public_key.pem
export const PUBLIC_KEY = `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAox1vvOi+i854DZUcmAvd
Vs6wvDTOrZe4OBciU4jwOFyXh9g2EONXA2z3KLU28PJyd8rjimMtCOpmzFjDJseS
Hf2SpQz8CS1Dlfnrfk6LmWwsBWAwVrHLryGWyMXsG/HGSX61O8ENo3pTDaA6/zvc
XIpPAmccVocuH/f+Cd79YauOaBzQHF7M57UEnZvX3s4O0P0co0q2nNuP0WUooqy5
qY7fSKOd9d5Pkp0h+qAyKTVukQFFIeKrKgnvA8PDOr3ljk5fapwnJl84HIP9OSGC
8zzUE51bJIqUjb3cvk5jUHUM1NQVDoBvSpvboxRc6+Kf0zsjXUTTSpus2kBeAM+s
KQIDAQAB
-----END PUBLIC KEY-----
`;
