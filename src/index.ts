import crypto from 'crypto'

import Hmac from '@alessiofrittoli/crypto-key/Hmac'
import Algorithm from '@alessiofrittoli/crypto-algorithm'
import Exception from '@alessiofrittoli/exception'
import { coerceToUint8Array, type CoerceToUint8ArrayInput } from '@alessiofrittoli/crypto-buffer/coercion'

import ErrorCode from './error'
import type Sign from './types'


class Signature
{
	private static Algorithm: Sign.AlgorithmJwkName = 'HS256'
	private static HashDigest: Sign.Hash = 'SHA-256'


	/**
	 * Sincronously create a signature with the given data.
	 * 
	 * @param	data		The data to sign.
	 * @param	key			The private key used for HMAC or the PEM private key for RSA, ECDSA and RSASSA-PSS signing algorithms.
	 * @param	algorithm	( Optional ) The Jwk Algorithm name to use. Default: `HS256`.
	 * @returns	The signature Buffer. Throws a new Exception on failure.
	 */
	static sign(
		data		: CoerceToUint8ArrayInput,
		key			: Sign.PrivateKey,
		algorithm	: Sign.AlgorithmJwkName = Signature.Algorithm,
	): Buffer
	{
		if ( ! data ) {
			throw new Exception( 'No data to sign has been provided.', {
				code: ErrorCode.Exception.EMPTY_VALUE,
			} )
		}
		if ( ! key ) {
			throw new Exception( 'No Private Key has been provided.', {
				code: ErrorCode.Signature.NO_PRIVATEKEY,
			} )
		}

		const digest		= Signature.jwkAlgToHash( algorithm ) || Signature.HashDigest
		const dataBuffer	= coerceToUint8Array( data )

		try {

			/** HMAC SHA signing algorithm */
			if ( algorithm.startsWith( 'HS' ) ) {

				let secret		= key as Sign.PrivateKey<'HMAC'>
				secret			= secret instanceof CryptoKey ? crypto.KeyObject.from( secret ) : secret
				
				return (
					Hmac.digest( dataBuffer, secret, digest )
				)
			}


			if ( algorithm === 'EdDSA' ) {

				let secret	= key as Sign.PrivateKey<'EdDSA'>
				secret		= secret instanceof CryptoKey ? crypto.KeyObject.from( secret ) : secret
				
				return crypto.sign( null, dataBuffer, secret )

			}


			/** RSASSA/RSASSA-PSS/ECDSA/DSA SHA signing algorithm */
			let secret	= key as Sign.PrivateKey<'RSA-PSS' | 'RSASSA-PKCS1-v1_5' | 'ECDSA' | 'DSA'>
			secret		= secret instanceof CryptoKey ? crypto.KeyObject.from( secret ) : secret
			const Sign	= crypto.createSign( digest )

			Sign.write( dataBuffer )
			Sign.end()

			return Sign.sign( secret )
			
		} catch ( error ) {
			throw new Exception( 'An error occured while creating the signature.', {
				code	: ErrorCode.Exception.UNKNOWN,
				cause	: error,
			} )
		}

	}


	/**
	 * Sincronously verify a signature.
	 * 
	 * @param	signature	The signature buffer.
	 * @param	data		The signed data.
	 * @param	key			The public key used for HMAC, or RSA, ECDSA and RSASSA-PSS signing verifications.
	 * @param	algorithm	( Optional ) The Jwk Algorithm name to use. Default: `HS256`.
	 * @returns	`true` if signature is valid. Throws a new Exception on failure.
	 */
	static isValid(
		signature	: CoerceToUint8ArrayInput,
		data		: CoerceToUint8ArrayInput,
		key			: Sign.PublicKey,
		algorithm	: Sign.AlgorithmJwkName = Signature.Algorithm,
	): true
	{
		if ( ! signature ) {
			throw new Exception( 'No signature provided.', {
				code: ErrorCode.Signature.NO_SIGN,
			} )
		}
		if ( ! data ) {
			throw new Exception( 'The signed data is needed for integrity controls.', {
				code: ErrorCode.Exception.EMPTY_VALUE,
			} )
		}
		if ( ! key ) {
			throw new Exception( 'No Public Key has been provided.', {
				code: ErrorCode.Signature.NO_PUBLICKEY,
			} )
		}

		const digest		= Signature.jwkAlgToHash( algorithm ) || Signature.HashDigest
		const signBuffer	= coerceToUint8Array( signature )
		const dataBuffer	= coerceToUint8Array( data )

		try {
			/** HMAC SHA signing algorithm */
			if ( algorithm.startsWith( 'HS' ) ) {

				let secret		= key as Sign.PublicKey<'HMAC'>
				secret			= secret instanceof CryptoKey ? crypto.KeyObject.from( secret ) : secret
				const isValid	= Hmac.isValid( Buffer.from( signBuffer ), dataBuffer, secret, digest )

				if ( ! isValid ) {
					throw new Exception( 'Invalid signature.', {
						code: ErrorCode.Signature.INVALID_SIGN,
					} )
				}

				return true

			}

			if ( algorithm === 'EdDSA' ) {

				let secret		= key as Sign.PublicKey<'EdDSA'>
				secret			= secret instanceof CryptoKey ? crypto.KeyObject.from( secret ) : secret
				const isValid	= crypto.verify( null, dataBuffer, secret, signBuffer )

				if ( ! isValid ) {
					throw new Exception( 'Invalid signature.', {
						code: ErrorCode.Signature.INVALID_SIGN,
					} )
				}
		
				return true

			}

			/** RSASSA/RSASSA-PSS/ECDSA/DSA SHA signing algorithm */
			let secret		= key as Sign.PublicKey<'RSA-PSS' | 'RSASSA-PKCS1-v1_5' | 'ECDSA' | 'DSA'>
			secret			= secret instanceof CryptoKey ? crypto.KeyObject.from( secret ) : secret
			const Verify	= crypto.createVerify( digest )

			Verify.write( dataBuffer )
			Verify.end()

			const isValid = Verify.verify( secret, signBuffer )

			if ( ! isValid ) {
				throw new Exception( 'Invalid signature.', {
					code: ErrorCode.Signature.INVALID_SIGN,
				} )
			}

			return true
		} catch ( error ) {
			if ( Exception.isException( error ) ) {
				throw error
			}
			throw new Exception( 'An error occured while verifying the signature.', {
				code	: ErrorCode.Exception.UNKNOWN,
				cause	: error,
			} )
		}

	}


	/**
	 * Get the Algorithm digest hash name.
	 *
	 * @param	jwkAlg The Algorithm.
	 * @returns	The corresponding Algorithm digest hash name.
	 */
	private static jwkAlgToHash( jwkAlg: Sign.AlgorithmJwkName )
	{
		return Algorithm.by( { jwkAlg } )?.hash
	}
}


export default Signature