import Exception from '@alessiofrittoli/exception/code'

export enum Signature
{
	INVALID_SIGN	= 'ERR:INVALIDSIGN',
	NO_SIGN			= 'ERR:NOSIGN',
	NO_PRIVATEKEY	= 'ERR:NOPRIVATEKEY',
	NO_PUBLICKEY	= 'ERR:NOPUBLICKEY',
}

const ErrorCode	= { Exception, Signature }
type ErrorCode	= MergedEnumValue<typeof ErrorCode>

export default ErrorCode