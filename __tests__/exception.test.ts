import Exception from '@alessiofrittoli/exception'

import Signature from '@/index'
import { ErrorCode } from '@/error'


describe( 'Signature.sign()', () => {

	it( 'throws a new Exception when no data to sign has been given', () => {
		try {
			Signature.sign( '', 'myscretkey', 'HS1' )
		} catch ( error ) {
			expect( error ).toBeInstanceOf( Exception )
			if ( Exception.isException<string, ErrorCode>( error ) ) {
				expect( error.code ).toBe( ErrorCode.EMPTY_VALUE )
			}
		}
	} )


	it( 'throws a new Exception with unsupported routine', async () => {

		try {
			Signature.sign( 'Data to be signed.', 'invalid private key', 'RS256' )
		} catch ( error ) {
			expect( error ).toBeInstanceOf( Exception )

			if ( Exception.isException<string, ErrorCode>( error ) ) {
				expect( error.code ).toBe( ErrorCode.UNKNOWN )
				expect( 'cause' in error ).toBe( true )
				const cause = error.cause as Error
				expect( cause.name ).toBe( 'Error' )
			}
		}

	} )
} )


describe( 'Signature.isValid()', () => {

	const data		= 'Data to sign.'
	const signature	= Buffer.from( 'd36d1407db3a339789b5762704db9481271bfc152e338f0aa900139e53bc288f', 'hex' )
	const secretKey	= 'mysecretkey'

	it( 'throws a new Exception when no signature has been given', () => {				
		try {
			Signature.isValid( '', data, secretKey )
		} catch ( error ) {
			
			expect( error ).toBeInstanceOf( Exception )
			
			if ( Exception.isException<string, ErrorCode>( error ) ) {
				expect( error.code ).toBe( ErrorCode.NO_SIGN )
			}
		}
	} )


	it( 'throws a new Exception when no data has been given', () => {				
		try {
			Signature.isValid( signature, '', secretKey )
		} catch ( error ) {
			expect( error ).toBeInstanceOf( Exception )
			
			if ( Exception.isException<string, ErrorCode>( error ) ) {
				expect( error.code ).toBe( ErrorCode.EMPTY_VALUE )
			}
		}
	} )


	it( 'throws a new Exception when no secret or Public Key has given', () => {
		try {
			Signature.isValid( signature, data, '' )
		} catch ( error ) {
			expect( error ).toBeInstanceOf( Exception )
			
			if ( Exception.isException<string, ErrorCode>( error ) ) {
				expect( error.code ).toBe( ErrorCode.NO_PUBLICKEY )
			}
		}
	} )


	it( 'throws a new Exception when signature is not valid', () => {
		try {
			Signature.isValid( 'invalid signature', data, secretKey )
		} catch ( error ) {
			expect( error ).toBeInstanceOf( Exception )
			
			if ( Exception.isException<string, ErrorCode>( error ) ) {
				expect( error.code ).toBe( ErrorCode.INVALID_SIGN )
			}
		}
	} )


	it( 'throws a new Exception when data has been altered', () => {
		try {
			Signature.isValid( signature, 'altered data', secretKey )
		} catch ( error ) {
			expect( error ).toBeInstanceOf( Exception )
			
			if ( Exception.isException<string, ErrorCode>( error ) ) {
				expect( error.code ).toBe( ErrorCode.INVALID_SIGN )
			}
		}
	} )


	it( 'throws a new Exception when using a wrong key', () => {
		try {
			Signature.isValid( signature, data, 'wrong secret key' )
		} catch ( error ) {
			expect( error ).toBeInstanceOf( Exception )
			
			if ( Exception.isException<string, ErrorCode>( error ) ) {
				expect( error.code ).toBe( ErrorCode.INVALID_SIGN )
			}
		}
	} )


	it( 'throws a new Exception with unsupported routine', async () => {

		try {
			Signature.isValid( signature, data, secretKey, 'DS1' ) // wrong algorithm used
		} catch ( error ) {
			expect( error ).toBeInstanceOf( Exception )

			if ( Exception.isException<string, ErrorCode>( error ) ) {
				expect( error.code ).toBe( ErrorCode.UNKNOWN )
				expect( 'cause' in error ).toBe( true )
				const cause = error.cause as Error
				expect( cause.name ).toBe( 'Error' )
			}
		}

	} )

} )