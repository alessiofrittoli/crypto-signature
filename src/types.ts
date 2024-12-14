import type crypto from 'crypto'
import type Algo from '@alessiofrittoli/crypto-algorithm/types'

namespace Sign
{
	/**
	 * Signature algorithm parameter.
	 * 
	 * @link https://datatracker.ietf.org/doc/html/rfc7518#section-3.1
	 */
	export type AlgorithmJwkName = Algo.JwkName
	export type Hash = Algo.Hash

	/**
	 * The private key used for HMAC or the PEM private key for RSA, ECDSA and RSASSA-PSS signing algorithms.
	 * 
	 */
	export type PrivateKey<
		TAlg extends Algo.Name = Algo.Name
	> = (
		TAlg extends `HMAC` ? ( crypto.BinaryLike | crypto.KeyObject | CryptoKey )
			: ( crypto.KeyLike | crypto.SignKeyObjectInput | crypto.SignPrivateKeyInput | CryptoKey )
	)


	/**
	 * The public key used for HMAC, or RSA, ECDSA and RSASSA-PSS signing verifications.
	 * 
	 */
	export type PublicKey<
		TAlg extends Algo.Name = Algo.Name
	> = (
		TAlg extends `HMAC` ? ( crypto.BinaryLike | crypto.KeyObject | CryptoKey )
			: ( crypto.KeyLike | crypto.VerifyKeyObjectInput | crypto.VerifyPublicKeyInput | crypto.VerifyJsonWebKeyInput | CryptoKey )
	)
}


export default Sign