import { ErrorCode as Exception } from '@alessiofrittoli/exception/code'

export const Signature = {
	INVALID_JWKNAME	: 'ERR:INVALIDJWKNAME',
	INVALID_SIGN	: 'ERR:INVALIDSIGN',
	NO_SIGN			: 'ERR:NOSIGN',
	NO_PRIVATEKEY	: 'ERR:NOPRIVATEKEY',
	NO_PUBLICKEY	: 'ERR:NOPUBLICKEY',
} as const

export const ErrorCode	= { ...Exception, ...Signature } as const
export type ErrorCode = typeof ErrorCode[ keyof typeof ErrorCode ]