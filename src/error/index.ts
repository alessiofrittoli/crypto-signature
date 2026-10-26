import { ErrorCode as ExceptionCode } from '@alessiofrittoli/exception/code'

export const ErrorCode = {
	...ExceptionCode,
	INVALID_JWKNAME: 'ERR:INVALIDJWKNAME',
	INVALID_SIGN: 'ERR:INVALIDSIGN',
	NO_SIGN: 'ERR:NOSIGN',
	NO_PRIVATEKEY: 'ERR:NOPRIVATEKEY',
	NO_PUBLICKEY: 'ERR:NOPUBLICKEY',
} as const

export type ErrorCode = (typeof ErrorCode)[keyof typeof ErrorCode]
