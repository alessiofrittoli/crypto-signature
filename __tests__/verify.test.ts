import crypto from 'crypto'
import Signature from '@/index'

describe( 'Signature.isValid()', () => {
	it( 'supports crypto KeyObject', () => {
		const key = crypto.createSecretKey( Buffer.from( 'myscretkey' ) )
		const signature = Signature.sign( 'My message', key, 'HS1' )

		expect(
			Signature.isValid( signature, 'My message', key, 'HS1' )
		).toBe( true )
	} )

	it( 'supports CryptoKey', async () => {
		const bytes		= 256
		const keypair	= crypto.generateKeyPairSync( 'rsa', {
			modulusLength		: bytes * 8,
			publicKeyEncoding	: { type: 'spki', format: 'der' },
			privateKeyEncoding	: { type: 'pkcs8', format: 'der' },
		} )
		
		const privateKey = await (
			crypto.subtle
				.importKey(
					'pkcs8', keypair.privateKey,
					{ name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
					true, [ 'sign' ]
				)
		)

		const publicKey = await (
			crypto.subtle
				.importKey(
					'spki', keypair.publicKey,
					{ name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
					true, [ 'verify' ]
				)
		)

		const signature = Signature.sign( 'My message', privateKey, 'RS256' )
		
		expect(
			Signature.isValid( signature, 'My message', publicKey, 'RS256' )
		).toBe( true )
	} )
} )


describe( 'Signature.isValid() - HMAC', () => {

	it( 'verifies a signature with HS1', () => {
		const signature = Signature.sign( 'My message', 'myscretkey', 'HS1' )

		expect(
			Signature.isValid( signature, 'My message', 'myscretkey', 'HS1' )
		).toBe( true )
	} )


	it( 'verifies a signature with HS256', () => {
		const signature = Signature.sign( 'My message', 'myscretkey' )

		expect(
			Signature.isValid( signature, 'My message', 'myscretkey' )
		).toBe( true )
	} )


	it( 'verifies a signature with HS384', () => {
		const signature = Signature.sign( 'My message', 'myscretkey', 'HS384' )

		expect(
			Signature.isValid( signature, 'My message', 'myscretkey', 'HS384' )
		).toBe( true )
	} )


	it( 'verifies a signature with HS512', () => {
		const signature = Signature.sign( 'My message', 'myscretkey', 'HS512' )

		expect(
			Signature.isValid( signature, 'My message', 'myscretkey', 'HS512' )
		).toBe( true )
	} )

} )


describe( 'Signature.isValid() - DSA', () => {

	const passphrase = 'my-private-key-optional-passphrase'
	const keypair = crypto.generateKeyPairSync( 'dsa', {
		modulusLength		: 2048,
		divisorLength		: 256,
		publicKeyEncoding	: { type: 'spki', format: 'pem' },
		privateKeyEncoding	: { type: 'pkcs8', format: 'pem', passphrase, cipher: 'aes-256-cbc' }
	} )

	it( 'verifies a signature with DS1', () => {
		const signature = Signature.sign( 'My message', {
			key			: keypair.privateKey,
			passphrase	: passphrase,
		}, 'DS1' )

		expect(
			Signature.isValid( signature, 'My message', keypair.publicKey, 'DS1' )
		).toBe( true )
	} )


	it( 'verifies a signature with DS256', () => {
		const signature = Signature.sign( 'My message', {
			key			: keypair.privateKey,
			passphrase	: passphrase,
		}, 'DS256' )

		expect(
			Signature.isValid( signature, 'My message', keypair.publicKey, 'DS256' )
		).toBe( true )
	} )


	it( 'verifies a signature with DS384', () => {
		const signature = Signature.sign( 'My message', {
			key			: keypair.privateKey,
			passphrase	: passphrase,
		}, 'DS384' )

		expect(
			Signature.isValid( signature, 'My message', keypair.publicKey, 'DS384' )
		).toBe( true )
	} )


	it( 'verifies a signature with DS512', () => {
		const signature = Signature.sign( 'My message', {
			key			: keypair.privateKey,
			passphrase	: passphrase,
		}, 'DS512' )

		expect(
			Signature.isValid( signature, 'My message', keypair.publicKey, 'DS512' )
		).toBe( true )
	} )

} )


describe( 'Signature.isValid() - EcDSA', () => {

	const passphrase = 'my-private-key-optional-passphrase'

	it( 'verifies a signature with ES256', () => {
		const keypair = crypto.generateKeyPairSync( 'ec', {
			namedCurve			: 'secp256k1',
			publicKeyEncoding	: { type: 'spki', format: 'pem' },
			privateKeyEncoding	: { type: 'pkcs8', format: 'pem', passphrase, cipher: 'aes-256-cbc' },
		} )

		const signature = Signature.sign( 'My message', {
			key			: keypair.privateKey,
			passphrase	: passphrase,
		}, 'ES256' )

		expect(
			Signature.isValid( signature, 'My message', keypair.publicKey, 'ES256' )
		).toBe( true )
	} )


	it( 'verifies a signature with ES384', () => {
		const keypair = crypto.generateKeyPairSync( 'ec', {
			namedCurve			: 'secp384r1',
			publicKeyEncoding	: { type: 'spki', format: 'pem' },
			privateKeyEncoding	: { type: 'pkcs8', format: 'pem', passphrase, cipher: 'aes-256-cbc' },
		} )

		const signature = Signature.sign( 'My message', {
			key			: keypair.privateKey,
			passphrase	: passphrase,
		}, 'ES384' )

		expect(
			Signature.isValid( signature, 'My message', keypair.publicKey, 'ES384' )
		).toBe( true )
	} )


	it( 'verifies a signature with ES512', () => {
		const keypair = crypto.generateKeyPairSync( 'ec', {
			namedCurve			: 'secp521r1',
			publicKeyEncoding	: { type: 'spki', format: 'pem' },
			privateKeyEncoding	: { type: 'pkcs8', format: 'pem', passphrase, cipher: 'aes-256-cbc' },
		} )

		const signature = Signature.sign( 'My message', {
			key			: keypair.privateKey,
			passphrase	: passphrase,
		}, 'ES512' )

		expect(
			Signature.isValid( signature, 'My message', keypair.publicKey, 'ES512' )
		).toBe( true )
	} )

} )


describe( 'Signature.isValid() - EdDSA', () => {

	it( 'verifies a signature with ed448', () => {

		const passphrase = 'my-private-key-optional-passphrase'
		const keypair = crypto.generateKeyPairSync( 'ed448', {
			publicKeyEncoding	: { type: 'spki', format: 'pem' },
			privateKeyEncoding	: { type: 'pkcs8', format: 'pem', passphrase, cipher: 'aes-256-cbc' }
		} )

		const signature = Signature.sign( 'My message', {
			key			: keypair.privateKey,
			passphrase	: passphrase,
		}, 'EdDSA' )

		expect(
			Signature.isValid( signature, 'My message', keypair.publicKey, 'EdDSA' )
		).toBe( true )
	} )


	it( 'verifies a signature with ed25519', () => {

		const passphrase = 'my-private-key-optional-passphrase'
		const keypair = crypto.generateKeyPairSync( 'ed25519', {
			publicKeyEncoding	: { type: 'spki', format: 'pem' },
			privateKeyEncoding	: { type: 'pkcs8', format: 'pem', passphrase, cipher: 'aes-256-cbc' }
		} )

		const signature = Signature.sign( 'My message', {
			key			: keypair.privateKey,
			passphrase	: passphrase,
		}, 'EdDSA' )

		expect(
			Signature.isValid( signature, 'My message', keypair.publicKey, 'EdDSA' )
		).toBe( true )
	} )

} )


describe( 'Signature.isValid() - RSA', () => {

	const bytes			= 256
	const passphrase	= 'my-private-key-optional-passphrase'
	const keypair		= crypto.generateKeyPairSync( 'rsa', {
		modulusLength		: bytes * 8,
		publicKeyEncoding	: { type: 'spki', format: 'pem' },
		privateKeyEncoding	: { type: 'pkcs1', format: 'pem', passphrase, cipher: 'aes-256-cbc' },
	} )


	it( 'verifies a signature with RS1', () => {
		const signature = Signature.sign( 'My message', {
			key			: keypair.privateKey,
			passphrase	: passphrase,
		}, 'RS1' )

		expect(
			Signature.isValid( signature, 'My message', keypair.publicKey, 'RS1' )
		).toBe( true )
	} )


	it( 'verifies a signature with RS256', () => {
		const signature = Signature.sign( 'My message', {
			key			: keypair.privateKey,
			passphrase	: passphrase,
		}, 'RS256' )

		expect(
			Signature.isValid( signature, 'My message', keypair.publicKey, 'RS256' )
		).toBe( true )
	} )


	it( 'verifies a signature with RS384', () => {
		const signature = Signature.sign( 'My message', {
			key			: keypair.privateKey,
			passphrase	: passphrase,
		}, 'RS384' )

		expect(
			Signature.isValid( signature, 'My message', keypair.publicKey, 'RS384' )
		).toBe( true )
	} )


	it( 'verifies a signature with RS512', () => {
		const signature = Signature.sign( 'My message', {
			key			: keypair.privateKey,
			passphrase	: passphrase,
		}, 'RS512' )

		expect(
			Signature.isValid( signature, 'My message', keypair.publicKey, 'RS512' )
		).toBe( true )
	} )

} )


describe( 'Signature.isValid() - RSASSA-PSS', () => {

	const bytes			= 256
	const passphrase	= 'my-private-key-optional-passphrase'


	it( 'verifies a signature with PS256', () => {

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

		expect(
			Signature.isValid( signature, 'My message', keypair.publicKey, 'PS256' )
		).toBe( true )
	} )


	it( 'verifies a signature with PS384', () => {

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

		expect(
			Signature.isValid( signature, 'My message', keypair.publicKey, 'PS384' )
		).toBe( true )
	} )


	it( 'verifies a signature with PS512', () => {

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

		expect(
			Signature.isValid( signature, 'My message', keypair.publicKey, 'PS512' )
		).toBe( true )
	} )

} )