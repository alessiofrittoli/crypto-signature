import crypto from 'crypto'
import { Signature } from '@/index'
import { Exception } from '@alessiofrittoli/exception'
import { ErrorCode } from '@/error'


describe( 'Signature.sign()', () => {

	const data		= 'Data to sign.'
	const secretKey	= 'mysecretkey'

	it( 'supports crypto KeyObject', () => {
		const key = crypto.createSecretKey( Buffer.from( secretKey ) )
		const signature = Signature.sign( data, key, 'HS1' )

		expect( signature.toString( 'base64url' ) )
			.toBe( '0S7AFWrfw61Y8N1y0ckESkZ5tgE' )
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

		const signature = Signature.sign( data, privateKey, 'RS256' )
		
		expect( signature.toString( 'base64url' ) )
			.toBeTruthy()
	} )


	it( 'throws a new Exception when no data to sign has been given', () => {
		try {
			Signature.sign( '', secretKey, 'HS1' )
		} catch ( error ) {
			expect( error ).toBeInstanceOf( Exception )
			if ( Exception.isException<string, ErrorCode>( error ) ) {
				expect( error.code ).toBe( ErrorCode.Exception.EMPTY_VALUE )
			}
		}
	} )


	it( 'throws a new Exception with unsupported routine', async () => {

		try {
			Signature.sign( 'Data to be signed.', 'invalid private key', 'RS256' )
		} catch ( error ) {
			expect( error ).toBeInstanceOf( Exception )

			if ( Exception.isException<string, ErrorCode>( error ) ) {
				expect( error.code ).toBe( ErrorCode.Exception.UNKNOWN )
				expect( 'cause' in error ).toBe( true )
				const cause = error.cause as Error
				expect( cause.name ).toBe( 'Error' )
			}
		}

	} )


	describe( 'HMAC', () => {
	
		it( 'creates a signature with HS1', () => {
			const signature = Signature.sign( data, secretKey, 'HS1' )
	
			expect( signature.toString( 'base64url' ) )
				.toBe( '0S7AFWrfw61Y8N1y0ckESkZ5tgE' )
		} )
	
	
		it( 'creates a signature with HS256', () => {
			const signature = Signature.sign( data, secretKey )
	
			expect( signature.toString( 'base64url' ) )
				.toBe( '020UB9s6M5eJtXYnBNuUgScb_BUuM48KqQATnlO8KI8' )
		} )
	
	
		it( 'creates a signature with HS384', () => {
			const signature = Signature.sign( data, secretKey, 'HS384' )
	
			expect( signature.toString( 'base64url' ) )
				.toBe( 'C8uu3ddmTZuSOM8PkVqiaJ6zDeLWMZI6oQojSlq536ujQFAOsYEvKQUHiQg_THpj' )
		} )
	
	
		it( 'creates a signature with HS512', () => {
			const signature = Signature.sign( data, secretKey, 'HS512' )
	
			expect( signature.toString( 'base64url' ) )
				.toBe( 'Mr2t0NHzI80_EfwwOFXKoiKpwe46jBbc7TRO-UpMNlzgHYeUkQEXy8aC4TpqnS0VHCk-Wnw5Q_ful_9qLKL3Ww' )
		} )
	
	} )
	
	
	describe( 'DSA', () => {
	
		const passphrase = 'my-private-key-optional-passphrase'
		const keypair = crypto.generateKeyPairSync( 'dsa', {
			modulusLength		: 2048,
			divisorLength		: 256,
			publicKeyEncoding	: { type: 'spki', format: 'pem' },
			privateKeyEncoding	: { type: 'pkcs8', format: 'pem', passphrase, cipher: 'aes-256-cbc' }
		} )
	
		it( 'creates a signature with DS1', () => {
			const signature = Signature.sign( data, {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			}, 'DS1' )
	
			expect( signature.length )
				.toBeGreaterThan( 0 )
		} )
	
	
		it( 'creates a signature with DS256', () => {
			const signature = Signature.sign( data, {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			}, 'DS256' )
	
			expect( signature.length )
				.toBeGreaterThan( 0 )
		} )
	
	
		it( 'creates a signature with DS384', () => {
			const signature = Signature.sign( data, {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			}, 'DS384' )
	
			expect( signature.length )
				.toBeGreaterThan( 0 )
		} )
	
	
		it( 'creates a signature with DS512', () => {
			const signature = Signature.sign( data, {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			}, 'DS512' )
	
			expect( signature.length )
				.toBeGreaterThan( 0 )
		} )
	
	} )
	
	
	describe( 'EcDSA', () => {
	
		const passphrase = 'my-private-key-optional-passphrase'
	
		it( 'creates a signature with ES256', () => {
			const keypair = crypto.generateKeyPairSync( 'ec', {
				namedCurve			: 'secp256k1',
				publicKeyEncoding	: { type: 'spki', format: 'pem' },
				privateKeyEncoding	: { type: 'pkcs8', format: 'pem', passphrase, cipher: 'aes-256-cbc' },
			} )
	
			const signature = Signature.sign( data, {
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
	
			const signature = Signature.sign( data, {
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
	
			const signature = Signature.sign( data, {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			}, 'ES512' )
	
			expect( signature.length )
				.toBeGreaterThan( 0 )
		} )
	
	} )
	
	
	describe( 'EdDSA', () => {
	
		const passphrase = 'my-private-key-optional-passphrase'
	
		it( 'creates a signature with ed448', () => {
			const keypair = crypto.generateKeyPairSync( 'ed448', {
				publicKeyEncoding	: { type: 'spki', format: 'pem' },
				privateKeyEncoding	: { type: 'pkcs8', format: 'pem', passphrase, cipher: 'aes-256-cbc' }
			} )
	
			const signature = Signature.sign( data, {
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
	
			const signature = Signature.sign( data, {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			}, 'EdDSA' )
	
			expect( signature.length )
				.toBeGreaterThan( 0 )
		} )
	
	} )
	
	
	describe( 'RSA', () => {
	
		const bytes			= 256
		const passphrase	= 'my-private-key-optional-passphrase'
		const keypair		= crypto.generateKeyPairSync( 'rsa', {
			modulusLength		: bytes * 8,
			publicKeyEncoding	: { type: 'spki', format: 'pem' },
			privateKeyEncoding	: { type: 'pkcs1', format: 'pem', passphrase, cipher: 'aes-256-cbc' },
		} )
	
	
		it( 'creates a signature with RS1', () => {
			const signature = Signature.sign( data, {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			}, 'RS1' )
	
			expect( signature.length )
				.toBeGreaterThan( 0 )
		} )
	
	
		it( 'creates a signature with RS256', () => {
			const signature = Signature.sign( data, {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			}, 'RS256' )
	
			expect( signature.length )
				.toBeGreaterThan( 0 )
		} )
	
	
		it( 'creates a signature with RS384', () => {
			const signature = Signature.sign( data, {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			}, 'RS384' )
	
			expect( signature.length )
				.toBeGreaterThan( 0 )
		} )
	
	
		it( 'creates a signature with RS512', () => {
			const signature = Signature.sign( data, {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			}, 'RS512' )
	
			expect( signature.length )
				.toBeGreaterThan( 0 )
		} )
	
	} )
	
	
	describe( 'RSASSA-PSS', () => {
	
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
	
			const signature = Signature.sign( data, {
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
	
			const signature = Signature.sign( data, {
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
	
			const signature = Signature.sign( data, {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			}, 'PS512' )
	
			expect( signature.length )
				.toBeGreaterThan( 0 )
		} )
	
	} )

} )


describe( 'Signature.isValid()', () => {

	const data		= 'Data to sign.'
	const signature	= Buffer.from( 'd36d1407db3a339789b5762704db9481271bfc152e338f0aa900139e53bc288f', 'hex' )
	const secretKey	= 'mysecretkey'

	it( 'supports crypto KeyObject', () => {
		const key = crypto.createSecretKey( Buffer.from( secretKey ) )
		const signature = Signature.sign( data, key, 'HS1' )

		expect(
			Signature.isValid( signature, data, key, 'HS1' )
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

		const signature = Signature.sign( data, privateKey, 'RS256' )
		
		expect(
			Signature.isValid( signature, data, publicKey, 'RS256' )
		).toBe( true )
	} )


	it( 'throws a new Exception when no signature has been given', () => {				
		try {
			Signature.isValid( '', data, secretKey )
		} catch ( error ) {
			
			expect( error ).toBeInstanceOf( Exception )
			
			if ( Exception.isException<string, ErrorCode>( error ) ) {
				expect( error.code ).toBe( ErrorCode.Signature.NO_SIGN )
			}
		}
	} )


	it( 'throws a new Exception when no data has been given', () => {				
		try {
			Signature.isValid( signature, '', secretKey )
		} catch ( error ) {
			expect( error ).toBeInstanceOf( Exception )
			
			if ( Exception.isException<string, ErrorCode>( error ) ) {
				expect( error.code ).toBe( ErrorCode.Exception.EMPTY_VALUE )
			}
		}
	} )


	it( 'throws a new Exception when no secret or Public Key has given', () => {
		try {
			Signature.isValid( signature, data, '' )
		} catch ( error ) {
			expect( error ).toBeInstanceOf( Exception )
			
			if ( Exception.isException<string, ErrorCode>( error ) ) {
				expect( error.code ).toBe( ErrorCode.Signature.NO_PUBLICKEY )
			}
		}
	} )


	it( 'throws a new Exception when signature is not valid', () => {
		try {
			Signature.isValid( 'invalid signature', data, secretKey )
		} catch ( error ) {
			expect( error ).toBeInstanceOf( Exception )
			
			if ( Exception.isException<string, ErrorCode>( error ) ) {
				expect( error.code ).toBe( ErrorCode.Signature.INVALID_SIGN )
			}
		}
	} )


	it( 'throws a new Exception when data has been altered', () => {
		try {
			Signature.isValid( signature, 'altered data', secretKey )
		} catch ( error ) {
			expect( error ).toBeInstanceOf( Exception )
			
			if ( Exception.isException<string, ErrorCode>( error ) ) {
				expect( error.code ).toBe( ErrorCode.Signature.INVALID_SIGN )
			}
		}
	} )


	it( 'throws a new Exception when using a wrong key', () => {
		try {
			Signature.isValid( signature, data, 'wrong secret key' )
		} catch ( error ) {
			expect( error ).toBeInstanceOf( Exception )
			
			if ( Exception.isException<string, ErrorCode>( error ) ) {
				expect( error.code ).toBe( ErrorCode.Signature.INVALID_SIGN )
			}
		}
	} )


	it( 'throws a new Exception with unsupported routine', async () => {

		try {
			Signature.isValid( signature, data, secretKey, 'DS1' ) // wrong algorithm used
		} catch ( error ) {
			expect( error ).toBeInstanceOf( Exception )

			if ( Exception.isException<string, ErrorCode>( error ) ) {
				expect( error.code ).toBe( ErrorCode.Exception.UNKNOWN )
				expect( 'cause' in error ).toBe( true )
				const cause = error.cause as Error
				expect( cause.name ).toBe( 'Error' )
			}
		}

	} )
	
	
	describe( 'HMAC', () => {
	
		it( 'verifies a signature with HS1', () => {
			const signature = Signature.sign( data, secretKey, 'HS1' )
	
			expect(
				Signature.isValid( signature, data, secretKey, 'HS1' )
			).toBe( true )
		} )
	
	
		it( 'verifies a signature with HS256', () => {
			const signature = Signature.sign( data, secretKey )
	
			expect(
				Signature.isValid( signature, data, secretKey )
			).toBe( true )
		} )
	
	
		it( 'verifies a signature with HS384', () => {
			const signature = Signature.sign( data, secretKey, 'HS384' )
	
			expect(
				Signature.isValid( signature, data, secretKey, 'HS384' )
			).toBe( true )
		} )
	
	
		it( 'verifies a signature with HS512', () => {
			const signature = Signature.sign( data, secretKey, 'HS512' )
	
			expect(
				Signature.isValid( signature, data, secretKey, 'HS512' )
			).toBe( true )
		} )
	
	} )
	
	
	describe( 'DSA', () => {
	
		const passphrase = 'my-private-key-optional-passphrase'
		const keypair = crypto.generateKeyPairSync( 'dsa', {
			modulusLength		: 2048,
			divisorLength		: 256,
			publicKeyEncoding	: { type: 'spki', format: 'pem' },
			privateKeyEncoding	: { type: 'pkcs8', format: 'pem', passphrase, cipher: 'aes-256-cbc' }
		} )
	
		it( 'verifies a signature with DS1', () => {
			const signature = Signature.sign( data, {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			}, 'DS1' )
	
			expect(
				Signature.isValid( signature, data, keypair.publicKey, 'DS1' )
			).toBe( true )
		} )
	
	
		it( 'verifies a signature with DS256', () => {
			const signature = Signature.sign( data, {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			}, 'DS256' )
	
			expect(
				Signature.isValid( signature, data, keypair.publicKey, 'DS256' )
			).toBe( true )
		} )
	
	
		it( 'verifies a signature with DS384', () => {
			const signature = Signature.sign( data, {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			}, 'DS384' )
	
			expect(
				Signature.isValid( signature, data, keypair.publicKey, 'DS384' )
			).toBe( true )
		} )
	
	
		it( 'verifies a signature with DS512', () => {
			const signature = Signature.sign( data, {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			}, 'DS512' )
	
			expect(
				Signature.isValid( signature, data, keypair.publicKey, 'DS512' )
			).toBe( true )
		} )
	
	} )
	
	
	describe( 'EcDSA', () => {
	
		const passphrase = 'my-private-key-optional-passphrase'
	
		it( 'verifies a signature with ES256', () => {
			const keypair = crypto.generateKeyPairSync( 'ec', {
				namedCurve			: 'secp256k1',
				publicKeyEncoding	: { type: 'spki', format: 'pem' },
				privateKeyEncoding	: { type: 'pkcs8', format: 'pem', passphrase, cipher: 'aes-256-cbc' },
			} )
	
			const signature = Signature.sign( data, {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			}, 'ES256' )
	
			expect(
				Signature.isValid( signature, data, keypair.publicKey, 'ES256' )
			).toBe( true )
		} )
	
	
		it( 'verifies a signature with ES384', () => {
			const keypair = crypto.generateKeyPairSync( 'ec', {
				namedCurve			: 'secp384r1',
				publicKeyEncoding	: { type: 'spki', format: 'pem' },
				privateKeyEncoding	: { type: 'pkcs8', format: 'pem', passphrase, cipher: 'aes-256-cbc' },
			} )
	
			const signature = Signature.sign( data, {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			}, 'ES384' )
	
			expect(
				Signature.isValid( signature, data, keypair.publicKey, 'ES384' )
			).toBe( true )
		} )
	
	
		it( 'verifies a signature with ES512', () => {
			const keypair = crypto.generateKeyPairSync( 'ec', {
				namedCurve			: 'secp521r1',
				publicKeyEncoding	: { type: 'spki', format: 'pem' },
				privateKeyEncoding	: { type: 'pkcs8', format: 'pem', passphrase, cipher: 'aes-256-cbc' },
			} )
	
			const signature = Signature.sign( data, {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			}, 'ES512' )
	
			expect(
				Signature.isValid( signature, data, keypair.publicKey, 'ES512' )
			).toBe( true )
		} )
	
	} )
	
	
	describe( 'EdDSA', () => {
	
		it( 'verifies a signature with ed448', () => {
	
			const passphrase = 'my-private-key-optional-passphrase'
			const keypair = crypto.generateKeyPairSync( 'ed448', {
				publicKeyEncoding	: { type: 'spki', format: 'pem' },
				privateKeyEncoding	: { type: 'pkcs8', format: 'pem', passphrase, cipher: 'aes-256-cbc' }
			} )
	
			const signature = Signature.sign( data, {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			}, 'EdDSA' )
	
			expect(
				Signature.isValid( signature, data, keypair.publicKey, 'EdDSA' )
			).toBe( true )
		} )
	
	
		it( 'verifies a signature with ed25519', () => {
	
			const passphrase = 'my-private-key-optional-passphrase'
			const keypair = crypto.generateKeyPairSync( 'ed25519', {
				publicKeyEncoding	: { type: 'spki', format: 'pem' },
				privateKeyEncoding	: { type: 'pkcs8', format: 'pem', passphrase, cipher: 'aes-256-cbc' }
			} )
	
			const signature = Signature.sign( data, {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			}, 'EdDSA' )
	
			expect(
				Signature.isValid( signature, data, keypair.publicKey, 'EdDSA' )
			).toBe( true )
		} )
	
	} )
	
	
	describe( 'RSA', () => {
	
		const bytes			= 256
		const passphrase	= 'my-private-key-optional-passphrase'
		const keypair		= crypto.generateKeyPairSync( 'rsa', {
			modulusLength		: bytes * 8,
			publicKeyEncoding	: { type: 'spki', format: 'pem' },
			privateKeyEncoding	: { type: 'pkcs1', format: 'pem', passphrase, cipher: 'aes-256-cbc' },
		} )
	
	
		it( 'verifies a signature with RS1', () => {
			const signature = Signature.sign( data, {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			}, 'RS1' )
	
			expect(
				Signature.isValid( signature, data, keypair.publicKey, 'RS1' )
			).toBe( true )
		} )
	
	
		it( 'verifies a signature with RS256', () => {
			const signature = Signature.sign( data, {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			}, 'RS256' )
	
			expect(
				Signature.isValid( signature, data, keypair.publicKey, 'RS256' )
			).toBe( true )
		} )
	
	
		it( 'verifies a signature with RS384', () => {
			const signature = Signature.sign( data, {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			}, 'RS384' )
	
			expect(
				Signature.isValid( signature, data, keypair.publicKey, 'RS384' )
			).toBe( true )
		} )
	
	
		it( 'verifies a signature with RS512', () => {
			const signature = Signature.sign( data, {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			}, 'RS512' )
	
			expect(
				Signature.isValid( signature, data, keypair.publicKey, 'RS512' )
			).toBe( true )
		} )
	
	} )
	
	
	describe( 'RSASSA-PSS', () => {
	
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
	
			const signature = Signature.sign( data, {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			}, 'PS256' )
	
			expect(
				Signature.isValid( signature, data, keypair.publicKey, 'PS256' )
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
	
			const signature = Signature.sign( data, {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			}, 'PS384' )
	
			expect(
				Signature.isValid( signature, data, keypair.publicKey, 'PS384' )
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
	
			const signature = Signature.sign( data, {
				key			: keypair.privateKey,
				passphrase	: passphrase,
			}, 'PS512' )
	
			expect(
				Signature.isValid( signature, data, keypair.publicKey, 'PS512' )
			).toBe( true )
		} )
	
	} )

} )