import { ErrorCode as Exception } from '@alessiofrittoli/exception/code'

export enum Signature
{
	INVALID_SIGN	= 'ERR:INVALIDSIGN',
	NO_SIGN			= 'ERR:NOSIGN',
	NO_PRIVATEKEY	= 'ERR:NOPRIVATEKEY',
	NO_PUBLICKEY	= 'ERR:NOPUBLICKEY',
}

export const ErrorCode = { Exception, Signature }
export type ErrorCode	= MergedEnumValue<typeof ErrorCode>