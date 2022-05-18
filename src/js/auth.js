// eslint-disable-next-line import/no-extraneous-dependencies
// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
const AWS = require('aws-sdk');
const Axios = require('axios');
const Cookie = require('cookie');
const Crypto = require('crypto');
const JsonWebToken = require('jsonwebtoken');
const JwkToPem = require('jwk-to-pem');
const QueryString = require('querystring');
const fs = require('fs');
const Log = require('./lib/log');

// Using global variables should be used for caching data that is unlikely
// to change across many invocations.
// see https://aws.amazon.com/fr/blogs/networking-and-content-delivery/leveraging-external-data-in-lambdaedge/
let discoveryDocument;
// let secretId;
let jwks;
let config;
let deps;
let log;

const AppDefaults = require('./lib/appdefaults');
let appDefaults = new AppDefaults();

/**
 * handle is the starting point for the lambda.
 *
 * @param {Object} event is the event that initiates the handler
 * @param {AWS.Context} ctx is the aws lambda context
 * @param {(Error, any) => undefined} cb is the aws callback to signal completion.  This is used
 * instead of the async method because it has more predictable behavior.
 * @param {object} setDependencies is a function that sets the dependencies  If this is undefined
 * (as it will be in production) the setDependencies function in the module will set the
 * dependencies.  If this value is specified (as it will be in tests) then deps will be
 * overwritten with the specified dependencies.
 */
exports.handle = async (event, ctx, cb, setDeps = setDependencies) => {
	log = new Log(event, ctx);

	log.debug('lambda starts (logger initialised)', { event: event });

	deps = setDeps(deps);
	try {
		await normalizeRequest(event);
		return await authenticate(event);
	} catch (err) {
		log.error(err.message, { event: event }, err);
		return getInternalServerErrorPayload(cb);
	}
};

/**
 * Tells whether authentication is required for a given target URI and a given
 * allowed patterns.
 *
 * The target URI is matched against a set of regular expressions defined in the
 * allowed patterns. If any of them matches then the function instantly returns
 * 'true' to indicate that the URI is allowed. Otherwise it returns 'false' to
 * indicate that the URI is not part of the white list.
 *
 * @param {string} request is the request contained in the cloudfront event.
 * @param {*} allowedURLPatterns an array of regular expressions that defined allowed URIs.
 * @returns false if the request URI matches one of the regular expressions defined in
 * the application defaults parameters, or true otherwise.
 */
function isURIAllowed(requestUri, allowedURLPatterns) {
	log.debug('evaluating request uri against a regex array', {requestUri, allowedURLPatterns});
	if (Array.isArray(allowedURLPatterns)) {
		for (curRegExIdx in allowedURLPatterns) {
			let curRegEx = allowedURLPatterns[curRegExIdx];
			log.debug('matching', { curRegExIdx, curRegEx });
			if (requestUri.match(curRegEx)) {
				log.debug('match found', curRegEx);
				return true;
			}
		};
	} else {
		log.error('the provided allowed regex array is not usable');
	}
	return false;
}

async function normalizeRequest(evt) {
	const request = evt.Records[0].cf.request;

	// Append 'index.html' to URI with trailing slash (folders)
	let requestUri = request.uri;
	log.debug('request URI normalization"', { evt } );

	let normalizedRequestUri = requestUri.replace(/\/$/, '\/' + appDefaults.defaultDocument)
	if (normalizedRequestUri !== request.uri) {
		log.debug('appended default document to request uri', {normalizedRequestUri});
		request.uri = normalizedRequestUri
	}

	requestUri = request.uri;
}

// setDepedencies is used to allow the overwriting of module-level dependencies for the purpose of
// testing.  It's basically dependency injection.
function setDependencies(dependencies) {
	if (dependencies === undefined || dependencies === null) {
		log.debug('setting up dependencies');
		return {
			axios: Axios,
			sm: new AWS.SecretsManager({ apiVersion: '2017-10-17', region: 'us-east-1' })
		};
	} else {
		log.debug('dependencies are already setup');
	}
	return dependencies;
}

// authenticate authenticates the user if they are a valid user, otherwise redirects accordingly.
async function authenticate(evt) {
	const { request } = evt.Records[0].cf;

	if (isURIAllowed(request.uri, appDefaults.noAuthRegEx) === true) {
		log.info('request URI (no authentication required): "' + request.uri + '"')
		return request;
	}

	// Further processing will require
	await prepareConfigGlobals();

	const { headers, querystring } = request;
	const queryString = QueryString.parse(querystring);
	// log.info(config.CALLBACK_PATH);
	log.info('request URI: "' + request.uri + '"');
	if (request.uri.startsWith(config.CALLBACK_PATH)) {
		log.trace('callback from OIDC provider received', {queryString});
		if (queryString.error) {
			log.debug('callback from OIDC provider contains an error');
			return handleInvalidQueryString(queryString);
		}

		if (queryString.code === undefined || queryString.code === null) {
			log.debug('callback from OIDC provider does not contain a code');
			return getUnauthorizedPayload('No Code Found', '', '');
		}

		log.debug('generating response with new JWT');
		return getNewJwtResponse({ evt, request, queryString, headers });
	}
	if ('cookie' in headers && 'TOKEN' in Cookie.parse(headers.cookie[0].value)) {
		log.debug('request received with TOKEN cookie');
		return getVerifyJwtResponse(request, headers);
	}

	log.debug('non-callback request received without TOKEN: Redirecting to OIDC provider');
	return getOidcRedirectPayload(request, headers);
}

// getVerifyJwtResponse gets the appropriate response for verified Jwt.
async function getVerifyJwtResponse(request, headers) {
	try {
		log.trace('verifying lambda JWT Response', { request, headers });
		const decoded = await verifyJwt(request, Cookie.parse(headers.cookie[0].value).TOKEN, config.PUBLIC_KEY.trim(), {
			algorithms: ['RS256']
		});
		log.trace('verified lambda JWT Response', {decoded});

		// Validate request URI against the set of audience
		if (isURIAllowed(request.uri, decoded.aud)) {
			return request;
		} else {
			return getUnauthorizedPayload(
				'Path not allowed',
				`User ${decoded.email || 'user'} is not allowed to watch this resource`,
				`Path "${request.uri}" is not part of the user's allowed folders`
			);
		}
	} catch (err) {
		switch (err.name) {
			case 'TokenExpiredError':
				log.warn('token expired, redirecting to OIDC provider', undefined, err);
				return getOidcRedirectPayload(request, headers);
			case 'JsonWebTokenError':
				log.warn('jwt error, unauthorized', undefined, err);
				return getUnauthorizedPayload('Json Web Token Error', err.message, '');
			default:
				log.warn('unknown JWT error, unauthorized', undefined, err);
				return getUnauthorizedPayload('Unauthorized.', `User is not permitted`, '');
		}
	}
}

// getNewJwtResponse returns the response required to redirect and get a new Jwt.
async function getNewJwtResponse({ evt, request, queryString, headers }) {
	try {
		config.TOKEN_REQUEST.code = queryString.code;
		log.trace('code details', { config, queryString });

		log.debug('requesting token from OIDC provider');
		const { idToken, decodedToken } = await getIdAndDecodedToken();

		log.trace('searching for JWK from discovery document', { jwks, decodedToken, idToken });
		const rawPem = jwks.keys.filter((k) => k.kid === decodedToken.header.kid)[0];
		if (rawPem === undefined) {
			throw new Error('unable to find expected pem in jwks keys');
		}
		const pem = JwkToPem(rawPem);

		log.trace('verifying JWT', { rawPem, pem });
		try {
			log.debug('verifying OIDC provider JWT Response');
			const decoded = await verifyJwt(request, idToken, pem, { algorithms: ['RS256'] });
			log.trace('verified OIDC provider JWT Response', {decoded});
			if (
				'cookie' in headers &&
				'NONCE' in Cookie.parse(headers.cookie[0].value) &&
				validateNonce(decoded.nonce, Cookie.parse(headers.cookie[0].value).NONCE)
			) {
				// Validate the redirection target URI against the set of user_folders.
				// We could wait until the browser hits us again with the lambda JWT but
				// performing this verification ASAP avoids unecessary traffic and can
				// help reducing the costs.
				if (isURIAllowed(queryString.state, decoded.user_folders)) {
					// Redirect to the actual resource with a lambda JWT TOKEN cookie.
					// This will trigger another request with the lambda TOKEN
					// user_folders will then be verified from the lambda JWT TOKEN cookie
					return getRedirectPayload({ evt, queryString, decodedToken, headers });
				} else {
					return getUnauthorizedPayload(
						'Unknown JWT',
						`User ${decoded.email || 'user'} is not permitted`,
						`Path "${request.uri}" is not part of the user's allowed folders`
					);
				}
			}
			return getUnauthorizedPayload('Nonce Verification Failed', '', '');
		} catch (err) {
			if (err === undefined || err === null || err.name === undefined || err.name === null) {
				log.warn('unknown named JWT error, unauthorized.', undefined, err);
				return getUnauthorizedPayload(
					'Unknown JWT',
					`User ${decodedToken.payload.email || 'user'} is not permitted`,
					''
				);
			}
			switch (err.name) {
				case 'TokenExpiredError':
					log.warn('token expired, redirecting to OIDC provider', undefined, err);
					return getOidcRedirectPayload(request, headers);
				case 'JsonWebTokenError':
					log.warn('jwt error, unauthorized', undefined, err);
					return getUnauthorizedPayload('Json Web Token Error', err.message, '');
				default:
					log.warn('unknown JWT error, unauthorized', undefined, err);
					return getUnauthorizedPayload(
						'Unknown JWT',
						`User ${decodedToken.payload.email || 'user'} is not permitted`,
						''
					);
			}
		}
	} catch (error) {
		log.error('internal server error', undefined, error);
		return getInternalServerErrorPayload();
	}
}

// getIdAndDecodedToken gets the id token and decoded version fo the token from the token
// endpoint.
async function getIdAndDecodedToken() {
	const tokenRequest = QueryString.stringify(config.TOKEN_REQUEST);

	log.trace('requesting access token.', { discoveryDocument, tokenRequest, config });
	const response = await deps.axios.post(discoveryDocument.token_endpoint, tokenRequest);
	log.trace('response', { response });

	const decodedToken = JsonWebToken.decode(response.data.id_token, {
		complete: true
	});
	log.trace('decodedToken', { decodedToken });

	return { idToken: response.data.id_token, decodedToken };
}

// verifyJwt wraps the callback-based JsonWebToken.verify function in a promise.
async function verifyJwt(request, token, pem, algorithms) {
	return new Promise((resolve, reject) => {
		JsonWebToken.verify(token, pem, algorithms, (err, decoded) => {
			if (err) {
				log.error('verifyJwt failed', { token, pem, algorithms }, err);
				return reject(err);
			}
			return resolve(decoded);
		});
	});
}

// handleInvalidQueryString creates an unauthorized response with the proper formatting when
// a querysting contains an error.
function handleInvalidQueryString(queryString) {
	const errors = {
		invalid_request: 'Invalid Request',
		unauthorized_client: 'Unauthorized Client',
		access_denied: 'Access Denied',
		unsupported_response_type: 'Unsupported Response Type',
		invalid_scope: 'Invalid Scope',
		server_error: 'Server Error',
		temporarily_unavailable: 'Temporarily Unavailable'
	};

	let error = '';
	let errorDescription = '';
	let errorUri = '';

	if (errors[queryString.error] != null) {
		error = errors[queryString.error];
	} else {
		error = queryString.error;
	}
	if (queryString.error_description != null) {
		errorDescription = queryString.error_description;
	} else {
		errorDescription = '';
	}

	if (queryString.error_uri != null) {
		errorUri = queryString.error_uri;
	} else {
		errorUri = '';
	}

	return getUnauthorizedPayload(error, errorDescription, errorUri);
}

// getNonceAndHash gets a nonce and hash.
function getNonceAndHash() {
	log.debug('generating nonce and digest')
	const nonce = Crypto.randomBytes(32).toString('hex');
	const hash = Crypto.createHmac('sha256', nonce).digest('hex');
	return { nonce, hash };
}

// validateNonce validates a nonce.
function validateNonce(nonce, hash) {
	log.trace('validating nonce', {nonce, hash})
	const other = Crypto.createHmac('sha256', nonce).digest('hex');
	return other === hash;
}

// setConfig sets the config object to the value from SecretsManager if it wasn't already set.
async function setConfig() {
	if (config === undefined) {
		let secretId = appDefaults.oidcSecret;
		const secret = await deps.sm.getSecretValue({ SecretId: secretId }).promise();
		const buff = new Buffer.from(JSON.parse(secret.SecretString).config, 'base64');
		const decodedval = JSON.parse(buff.toString('utf-8'));
		config = decodedval;

		log.trace('OIDC provider config not cached and therefore retrieved from SecretsManager...', {secretId, config});
	} else {
		log.trace('re-using OIDC provider config from cached value !', {config});
	}
}

// setDiscoveryDocument sets the discoveryDocument object if it wasn't already set.
async function setDiscoveryDocument() {
	if (discoveryDocument === undefined) {
		let discoveryDocumentURI = config.DISCOVERY_DOCUMENT;
		discoveryDocument = (await deps.axios.get(discoveryDocumentURI)).data;

		log.trace('OIDC discovery document was not cached and therefore retrieved from OIDC provider', {discoveryDocumentURI, discoveryDocument});
	} else {
		log.trace('re-using OIDC discovery document from cached value !', {discoveryDocument});
	}
}

// setJwks sets the jwks object if it wasn't already set.
async function setJwks() {
	if (jwks === undefined) {
		if (
			discoveryDocument &&
			(discoveryDocument.jwks_uri === undefined || discoveryDocument.jwks_uri === null)
		) {
			throw new Error('Unable to find JWK in discovery document');
		}

		let jwksURI = discoveryDocument.jwks_uri;
		jwks = (await deps.axios.get(jwksURI)).data;

		log.trace('JWKS data not cached and therfore retrieved from OIDC provider...', {jwksURI, jwks});
	} else {
		log.trace('re-using JWKS data from cached value !', {jwks});
	}
}

// prepareConfigGlobals sets up all the lambda globals if they are not already set.
async function prepareConfigGlobals() {
	log.debug('preparing global configuration variables...');
	await setConfig();
	await setDiscoveryDocument();
	await setJwks();
}

// getRedirectPayload gets the actual 302 redirect payload
function getRedirectPayload({ evt, queryString, decodedToken, headers }) {
	const response = {
		status: '302',
		statusDescription: 'Found',
		body: 'ID token retrieved.',
		headers: {
			location: [
				{
					key: 'Location',
					value:// config.AUTH_REQUEST.redirect_uri + queryString.state
						evt.Records[0].cf.config.test !== undefined
							? config.AUTH_REQUEST.redirect_uri + queryString.state
							: queryString.state
				}
			],
			'set-cookie': [
				{
					key: 'Set-Cookie',
					value: Cookie.serialize(
						'TOKEN',
						JsonWebToken.sign({}, config.PRIVATE_KEY.trim(), {
							audience: headers.host[0].value,
							subject: decodedToken.payload.email,
							expiresIn: config.SESSION_DURATION,
							algorithm: 'RS256',
							audience: decodedToken.payload.user_folders
						}),
						{
							path: '/',
							maxAge: config.SESSION_DURATION
						}
					)
				},
				{
					key: 'Set-Cookie',
					value: Cookie.serialize('NONCE', '', {
						path: '/',
						expires: new Date(1970, 1, 1, 0, 0, 0, 0)
					})
				}
			]
		}
	};
	log.trace('setting cookie and redirecting', { response });
	return response;
}

// redirect generates an appropriate redirect response.
function getOidcRedirectPayload(request) {
	const { nonce, hash } = getNonceAndHash();
	config.AUTH_REQUEST.nonce = nonce;
	config.AUTH_REQUEST.state = request.uri; // Redirect to Authorization Server

	const response = {
		status: '302',
		statusDescription: 'Found',
		body: 'Redirecting to OIDC provider',
		headers: {
			location: [
				{
					key: 'Location',
					value: `${discoveryDocument.authorization_endpoint}?${QueryString.stringify(
						config.AUTH_REQUEST
					)}`
				}
			],
			'set-cookie': [
				{
					key: 'Set-Cookie',
					value: Cookie.serialize('TOKEN', '', {
						path: '/',
						expires: new Date(1970, 1, 1, 0, 0, 0, 0)
					})
				},
				{
					key: 'Set-Cookie',
					value: Cookie.serialize('NONCE', hash, {
						path: '/',
						httpOnly: true
					})
				}
			]
		}
	};
	log.trace('redirecting to OIDC provider', { response });
	return response;
}

// getUnauthorizedPayload generates an appropriate unauthorized response.
function getUnauthorizedPayload(error, errorDescription, errorUri) {
	const body = `<!DOCTYPE html>
  <html lang="en">
  <head>
      <!-- Simple HttpErrorPages | MIT License | https://github.com/AndiDittrich/HttpErrorPages -->
      <meta charset="utf-8" /><meta http-equiv="X-UA-Compatible" content="IE=edge" /><meta name="viewport" content="width=device-width, initial-scale=1" />
      <title>We've got some trouble | 401 - Unauthorized</title>
      <style type="text/css">/*! normalize.css v5.0.0 | MIT License | github.com/necolas/normalize.css */html{font-family:sans-serif;line-height:1.15;-ms-text-size-adjust:100%;-webkit-text-size-adjust:100%}body{margin:0}article,aside,footer,header,nav,section{display:block}h1{font-size:2em;margin:.67em 0}figcaption,figure,main{display:block}figure{margin:1em 40px}hr{box-sizing:content-box;height:0;overflow:visible}pre{font-family:monospace,monospace;font-size:1em}a{background-color:transparent;-webkit-text-decoration-skip:objects}a:active,a:hover{outline-width:0}abbr[title]{border-bottom:none;text-decoration:underline;text-decoration:underline dotted}b,strong{font-weight:inherit}b,strong{font-weight:bolder}code,kbd,samp{font-family:monospace,monospace;font-size:1em}dfn{font-style:italic}mark{background-color:#ff0;color:#000}small{font-size:80%}sub,sup{font-size:75%;line-height:0;position:relative;vertical-align:baseline}sub{bottom:-.25em}sup{top:-.5em}audio,video{display:inline-block}audio:not([controls]){display:none;height:0}img{border-style:none}svg:not(:root){overflow:hidden}button,input,optgroup,select,textarea{font-family:sans-serif;font-size:100%;line-height:1.15;margin:0}button,input{overflow:visible}button,select{text-transform:none}[type=reset],[type=submit],button,html [type=button]{-webkit-appearance:button}[type=button]::-moz-focus-inner,[type=reset]::-moz-focus-inner,[type=submit]::-moz-focus-inner,button::-moz-focus-inner{border-style:none;padding:0}[type=button]:-moz-focusring,[type=reset]:-moz-focusring,[type=submit]:-moz-focusring,button:-moz-focusring{outline:1px dotted ButtonText}fieldset{border:1px solid silver;margin:0 2px;padding:.35em .625em .75em}legend{box-sizing:border-box;color:inherit;display:table;max-width:100%;padding:0;white-space:normal}progress{display:inline-block;vertical-align:baseline}textarea{overflow:auto}[type=checkbox],[type=radio]{box-sizing:border-box;padding:0}[type=number]::-webkit-inner-spin-button,[type=number]::-webkit-outer-spin-button{height:auto}[type=search]{-webkit-appearance:textfield;outline-offset:-2px}[type=search]::-webkit-search-cancel-button,[type=search]::-webkit-search-decoration{-webkit-appearance:none}::-webkit-file-upload-button{-webkit-appearance:button;font:inherit}details,menu{display:block}summary{display:list-item}canvas{display:inline-block}template{display:none}[hidden]{display:none}/*! Simple HttpErrorPages | MIT X11 License | https://github.com/AndiDittrich/HttpErrorPages */body,html{width:100%;height:100%;background-color:#21232a}body{color:#fff;text-align:center;text-shadow:0 2px 4px rgba(0,0,0,.5);padding:0;min-height:100%;-webkit-box-shadow:inset 0 0 100px rgba(0,0,0,.8);box-shadow:inset 0 0 100px rgba(0,0,0,.8);display:table;font-family:"Open Sans",Arial,sans-serif}h1{font-family:inherit;font-weight:500;line-height:1.1;color:inherit;font-size:36px}h1 small{font-size:68%;font-weight:400;line-height:1;color:#777}a{text-decoration:none;color:#fff;font-size:inherit;border-bottom:dotted 1px #707070}.lead{color:silver;font-size:21px;line-height:1.4}.cover{display:table-cell;vertical-align:middle;padding:0 20px}footer{position:fixed;width:100%;height:40px;left:0;bottom:0;color:#a0a0a0;font-size:14px}</style>
  </head>
  <body>
      <div class="cover"><h1>${error}</h1><small>Error 401</small><p class="lead">${errorDescription}</p><p>${errorUri}</p></div>
      <footer><p><a href="https://github.com/widen/cloudfront-auth">cloudfront-auth</a></p></footer>
  </body>
  </html>
  `;

	return {
		body,
		status: '401',
		statusDescription: 'Unauthorized',
		headers: {
			'set-cookie': [
				{
					key: 'Set-Cookie',
					value: Cookie.serialize('TOKEN', '', {
						path: '/',
						expires: new Date(1970, 1, 1, 0, 0, 0, 0)
					})
				},
				{
					key: 'Set-Cookie',
					value: Cookie.serialize('NONCE', '', {
						path: '/',
						expires: new Date(1970, 1, 1, 0, 0, 0, 0)
					})
				}
			]
		}
	};
}

// getInternalServerErrorPayload returns an appropriate InternalServerError response.
function getInternalServerErrorPayload() {
	const body = `<!DOCTYPE html>
  <html lang="en">
  <head>
      <!-- Simple HttpErrorPages | MIT License | https://github.com/AndiDittrich/HttpErrorPages -->
      <meta charset="utf-8" /><meta http-equiv="X-UA-Compatible" content="IE=edge" /><meta name="viewport" content="width=device-width, initial-scale=1" />
      <title>We've got some trouble | 500 - Internal Server Error</title>
      <style type="text/css">/*! normalize.css v5.0.0 | MIT License | github.com/necolas/normalize.css */html{font-family:sans-serif;line-height:1.15;-ms-text-size-adjust:100%;-webkit-text-size-adjust:100%}body{margin:0}article,aside,footer,header,nav,section{display:block}h1{font-size:2em;margin:.67em 0}figcaption,figure,main{display:block}figure{margin:1em 40px}hr{box-sizing:content-box;height:0;overflow:visible}pre{font-family:monospace,monospace;font-size:1em}a{background-color:transparent;-webkit-text-decoration-skip:objects}a:active,a:hover{outline-width:0}abbr[title]{border-bottom:none;text-decoration:underline;text-decoration:underline dotted}b,strong{font-weight:inherit}b,strong{font-weight:bolder}code,kbd,samp{font-family:monospace,monospace;font-size:1em}dfn{font-style:italic}mark{background-color:#ff0;color:#000}small{font-size:80%}sub,sup{font-size:75%;line-height:0;position:relative;vertical-align:baseline}sub{bottom:-.25em}sup{top:-.5em}audio,video{display:inline-block}audio:not([controls]){display:none;height:0}img{border-style:none}svg:not(:root){overflow:hidden}button,input,optgroup,select,textarea{font-family:sans-serif;font-size:100%;line-height:1.15;margin:0}button,input{overflow:visible}button,select{text-transform:none}[type=reset],[type=submit],button,html [type=button]{-webkit-appearance:button}[type=button]::-moz-focus-inner,[type=reset]::-moz-focus-inner,[type=submit]::-moz-focus-inner,button::-moz-focus-inner{border-style:none;padding:0}[type=button]:-moz-focusring,[type=reset]:-moz-focusring,[type=submit]:-moz-focusring,button:-moz-focusring{outline:1px dotted ButtonText}fieldset{border:1px solid silver;margin:0 2px;padding:.35em .625em .75em}legend{box-sizing:border-box;color:inherit;display:table;max-width:100%;padding:0;white-space:normal}progress{display:inline-block;vertical-align:baseline}textarea{overflow:auto}[type=checkbox],[type=radio]{box-sizing:border-box;padding:0}[type=number]::-webkit-inner-spin-button,[type=number]::-webkit-outer-spin-button{height:auto}[type=search]{-webkit-appearance:textfield;outline-offset:-2px}[type=search]::-webkit-search-cancel-button,[type=search]::-webkit-search-decoration{-webkit-appearance:none}::-webkit-file-upload-button{-webkit-appearance:button;font:inherit}details,menu{display:block}summary{display:list-item}canvas{display:inline-block}template{display:none}[hidden]{display:none}/*! Simple HttpErrorPages | MIT X11 License | https://github.com/AndiDittrich/HttpErrorPages */body,html{width:100%;height:100%;background-color:#21232a}body{color:#fff;text-align:center;text-shadow:0 2px 4px rgba(0,0,0,.5);padding:0;min-height:100%;-webkit-box-shadow:inset 0 0 100px rgba(0,0,0,.8);box-shadow:inset 0 0 100px rgba(0,0,0,.8);display:table;font-family:"Open Sans",Arial,sans-serif}h1{font-family:inherit;font-weight:500;line-height:1.1;color:inherit;font-size:36px}h1 small{font-size:68%;font-weight:400;line-height:1;color:#777}a{text-decoration:none;color:#fff;font-size:inherit;border-bottom:dotted 1px #707070}.lead{color:silver;font-size:21px;line-height:1.4}.cover{display:table-cell;vertical-align:middle;padding:0 20px}footer{position:fixed;width:100%;height:40px;left:0;bottom:0;color:#a0a0a0;font-size:14px}</style>
  </head>
  <body>
      <div class="cover"><h1>Internal Server Error <small>Error 500</small></h1></div>
  </body>
  </html>
  `;

	return { status: '500', statusDescription: 'Internal Server Error', body };
}
