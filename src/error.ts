import Exception from '@alessiofrittoli/exception/code'

enum Signature
{
	INVALID_SIGN	= 'ERR:INVALIDSIGN',
	NO_SIGN			= 'ERR:NOSIGN',
	NO_PRIVATEKEY	= 'ERR:NOPRIVATEKEY',
	NO_PUBLICKEY	= 'ERR:NOPUBLICKEY',
}

const ErrorCode	= { Exception, Signature }
type ErrorCode	= MergedEnumValue<typeof ErrorCode>

export default ErrorCode