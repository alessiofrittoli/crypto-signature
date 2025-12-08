import { ErrorCode as Exception } from '@alessiofrittoli/exception/code'

const Signature = {
	INVALID_JWKNAME	: 'ERR:INVALIDJWKNAME',
	INVALID_SIGN	: 'ERR:INVALIDSIGN',
	NO_SIGN			: 'ERR:NOSIGN',
	NO_PRIVATEKEY	: 'ERR:NOPRIVATEKEY',
	NO_PUBLICKEY	: 'ERR:NOPUBLICKEY',
} as const

export const ErrorCode	= { ...Exception, ...Signature }
export type ErrorCode = typeof ErrorCode[ keyof typeof ErrorCode ]