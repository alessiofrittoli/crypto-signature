import crypto from 'crypto'
import Signature from '@/index'


describe( 'Signature.sign() - HMAC', () => {

	it( 'creates a signature with HS1', () => {
		const signature = Signature.sign( 'My message', 'myscretkey', 'HS1' )

		expect( signature.toString( 'base64url' ) )
			.toBe( 'MI446pz8PBXelRlxq7Ihw2AraVU' )
	} )


	it( 'creates a signature with HS256', () => {
		const signature = Signature.sign( 'My message', 'myscretkey' )

		expect( signature.toString( 'base64url' ) )
			.toBe( 'itK0p6yy8oE-sqedp-uHEpAHAMsAmmSe-En5bQ2QlVo' )
	} )


	it( 'creates a signature with HS384', () => {
		const signature = Signature.sign( 'My message', 'myscretkey', 'HS384' )

		expect( signature.toString( 'base64url' ) )
			.toBe( 'QxGoN6Yr5yU5FjAV-ruQqxrF1G8ELqHnQus9YmDOgcKiN6lmxXh1T21e8TpNq0PB' )
	} )


	it( 'creates a signature with HS512', () => {
		const signature = Signature.sign( 'My message', 'myscretkey', 'HS512' )

		expect( signature.toString( 'base64url' ) )
			.toBe( 'GGBBG9ajjWbTChCP6u1jVuPJNt5QUv6Zj4VGe3R2N9F6XmvYWLW3F1xUI3OKhE1RIp0uofQJbtl-28rLMRG_cA' )
	} )

} )


describe( 'Signature.sign() - DSA', () => {

	const passphrase = 'my-private-key-optional-passphrase'
	const keypair = crypto.generateKeyPairSync( 'dsa', {
		modulusLength		: 2048,
		divisorLength		: 256,
		publicKeyEncoding	: { type: 'spki', format: 'pem' },
		privateKeyEncoding	: { type: 'pkcs8', format: 'pem', passphrase, cipher: 'aes-256-cbc' }
	} )

	it( 'creates a signature with DS1', () => {
		const signature = Signature.sign( 'My message', {
			key			: keypair.privateKey,
			passphrase	: passphrase,
		}, 'DS1' )

		expect( signature.length )
			.toBeGreaterThan( 0 )
	} )


	it( 'creates a signature with DS256', () => {
		const signature = Signature.sign( 'My message', {
			key			: keypair.privateKey,
			passphrase	: passphrase,
		}, 'DS256' )

		expect( signature.length )
			.toBeGreaterThan( 0 )
	} )


	it( 'creates a signature with DS384', () => {
		const signature = Signature.sign( 'My message', {
			key			: keypair.privateKey,
			passphrase	: passphrase,
		}, 'DS384' )

		expect( signature.length )
			.toBeGreaterThan( 0 )
	} )


	it( 'creates a signature with DS512', () => {
		const signature = Signature.sign( 'My message', {
			key			: keypair.privateKey,
			passphrase	: passphrase,
		}, 'DS512' )

		expect( signature.length )
			.toBeGreaterThan( 0 )
	} )

} )


describe( 'Signature.sign() - EcDSA', () => {

	const passphrase = 'my-private-key-optional-passphrase'

	it( 'creates a signature with ES256', () => {
		const keypair = crypto.generateKeyPairSync( 'ec', {
			namedCurve			: 'secp256k1',
			publicKeyEncoding	: { type: 'spki', format: 'pem' },
			privateKeyEncoding	: { type: 'pkcs8', format: 'pem', passphrase, cipher: 'aes-256-cbc' },
		} )

		const signature = Signature.sign( 'My message', {
			key			: keypair.privateKey,
			passphrase	: passphrase,
		}, 'ES256' )

		expect( signature.length )
			.toBeGreaterThan( 0 )
	} )


	it( 'creates a signature with ES384', () => {
		const keypair = crypto.generateKeyPairSync( 'ec', {
			namedCurve			: 'secp384r1',
			publicKeyEncoding	: { type: 'spki', format: 'pem' },
			privateKeyEncoding	: { type: 'pkcs8', format: 'pem', passphrase, cipher: 'aes-256-cbc' },
		} )

		const signature = Signature.sign( 'My message', {
			key			: keypair.privateKey,
			passphrase	: passphrase,
		}, 'ES384' )

		expect( signature.length )
			.toBeGreaterThan( 0 )
	} )


	it( 'creates a signature with ES512', () => {
		const keypair = crypto.generateKeyPairSync( 'ec', {
			namedCurve			: 'secp521r1',
			publicKeyEncoding	: { type: 'spki', format: 'pem' },
			privateKeyEncoding	: { type: 'pkcs8', format: 'pem', passphrase, cipher: 'aes-256-cbc' },
		} )

		const signature = Signature.sign( 'My message', {
			key			: keypair.privateKey,
			passphrase	: passphrase,
		}, 'ES512' )

		expect( signature.length )
			.toBeGreaterThan( 0 )
	} )

} )


describe( 'Signature.sign() - EdDSA', () => {

	const passphrase = 'my-private-key-optional-passphrase'

	it( 'creates a signature with ed448', () => {
		const keypair = crypto.generateKeyPairSync( 'ed448', {
			publicKeyEncoding	: { type: 'spki', format: 'pem' },
			privateKeyEncoding	: { type: 'pkcs8', format: 'pem', passphrase, cipher: 'aes-256-cbc' }
		} )

		const signature = Signature.sign( 'My message', {
			key			: keypair.privateKey,
			passphrase	: passphrase,
		}, 'EdDSA' )

		expect( signature.length )
			.toBeGreaterThan( 0 )
	} )


	it( 'creates a signature with ed25519', () => {
		const keypair = crypto.generateKeyPairSync( 'ed25519', {
			publicKeyEncoding	: { type: 'spki', format: 'pem' },
			privateKeyEncoding	: { type: 'pkcs8', format: 'pem', passphrase, cipher: 'aes-256-cbc' }
		} )

		const signature = Signature.sign( 'My message', {
			key			: keypair.privateKey,
			passphrase	: passphrase,
		}, 'EdDSA' )

		expect( signature.length )
			.toBeGreaterThan( 0 )
	} )

} )


describe( 'Signature.sign() - RSA', () => {

	const bytes			= 256
	const passphrase	= 'my-private-key-optional-passphrase'
	const keypair		= crypto.generateKeyPairSync( 'rsa', {
		modulusLength		: bytes * 8,
		publicKeyEncoding	: { type: 'spki', format: 'pem' },
		privateKeyEncoding	: { type: 'pkcs1', format: 'pem', passphrase, cipher: 'aes-256-cbc' },
	} )


	it( 'creates a signature with RS1', () => {
		const signature = Signature.sign( 'My message', {
			key			: keypair.privateKey,
			passphrase	: passphrase,
		}, 'RS1' )

		expect( signature.length )
			.toBeGreaterThan( 0 )
	} )


	it( 'creates a signature with RS256', () => {
		const signature = Signature.sign( 'My message', {
			key			: keypair.privateKey,
			passphrase	: passphrase,
		}, 'RS256' )

		expect( signature.length )
			.toBeGreaterThan( 0 )
	} )


	it( 'creates a signature with RS384', () => {
		const signature = Signature.sign( 'My message', {
			key			: keypair.privateKey,
			passphrase	: passphrase,
		}, 'RS384' )

		expect( signature.length )
			.toBeGreaterThan( 0 )
	} )


	it( 'creates a signature with RS512', () => {
		const signature = Signature.sign( 'My message', {
			key			: keypair.privateKey,
			passphrase	: passphrase,
		}, 'RS512' )

		expect( signature.length )
			.toBeGreaterThan( 0 )
	} )

} )


describe( 'Signature.sign() - RSASSA-PSS', () => {

	const bytes			= 256
	const passphrase	= 'my-private-key-optional-passphrase'


	it( 'creates a signature with PS256', () => {

		const hash = 'SHA-256'
		/** RSASSA-PSS using `hash` and MGF1 with `hash` */
		const keypair = crypto.generateKeyPairSync( 'rsa-pss', {
			modulusLength		: bytes * 8,
			hashAlgorithm		: hash,
			mgf1HashAlgorithm	: hash,
			publicKeyEncoding	: { type: 'spki', format: 'pem' },
			privateKeyEncoding	: { type: 'pkcs8', format: 'pem', passphrase, cipher: 'aes-256-cbc' },
		} )

		const signature = Signature.sign( 'My message', {
			key			: keypair.privateKey,
			passphrase	: passphrase,
		}, 'PS256' )

		expect( signature.length )
			.toBeGreaterThan( 0 )
	} )


	it( 'creates a signature with PS384', () => {

		const hash = 'SHA-384'
		/** RSASSA-PSS using `hash` and MGF1 with `hash` */
		const keypair = crypto.generateKeyPairSync( 'rsa-pss', {
			modulusLength		: bytes * 8,
			hashAlgorithm		: hash,
			mgf1HashAlgorithm	: hash,
			publicKeyEncoding	: { type: 'spki', format: 'pem' },
			privateKeyEncoding	: { type: 'pkcs8', format: 'pem', passphrase, cipher: 'aes-256-cbc' },
		} )

		const signature = Signature.sign( 'My message', {
			key			: keypair.privateKey,
			passphrase	: passphrase,
		}, 'PS384' )

		expect( signature.length )
			.toBeGreaterThan( 0 )
	} )


	it( 'creates a signature with PS512', () => {

		const hash = 'SHA-512'
		/** RSASSA-PSS using `hash` and MGF1 with `hash` */
		const keypair = crypto.generateKeyPairSync( 'rsa-pss', {
			modulusLength		: bytes * 8,
			hashAlgorithm		: hash,
			mgf1HashAlgorithm	: hash,
			publicKeyEncoding	: { type: 'spki', format: 'pem' },
			privateKeyEncoding	: { type: 'pkcs8', format: 'pem', passphrase, cipher: 'aes-256-cbc' },
		} )

		const signature = Signature.sign( 'My message', {
			key			: keypair.privateKey,
			passphrase	: passphrase,
		}, 'PS512' )

		expect( signature.length )
			.toBeGreaterThan( 0 )
	} )

} )