# Crypto Signature 🔏

[![NPM Latest Version][version-badge]][npm-url] [![Coverage Status][coverage-badge]][coverage-url] [![Socket Status][socket-badge]][socket-url] [![NPM Monthly Downloads][downloads-badge]][npm-url] [![Dependencies][deps-badge]][deps-url]

[![GitHub Sponsor][sponsor-badge]][sponsor-url]

[version-badge]: https://img.shields.io/npm/v/%40alessiofrittoli%2Fcrypto-signature
[npm-url]: https://npmjs.org/package/%40alessiofrittoli%2Fcrypto-signature
[coverage-badge]: https://coveralls.io/repos/github/alessiofrittoli/crypto-signature/badge.svg
[coverage-url]: https://coveralls.io/github/alessiofrittoli/crypto-signature
[socket-badge]: https://socket.dev/api/badge/npm/package/@alessiofrittoli/crypto-signature
[socket-url]: https://socket.dev/npm/package/@alessiofrittoli/crypto-signature/overview
[downloads-badge]: https://img.shields.io/npm/dm/%40alessiofrittoli%2Fcrypto-signature.svg
[deps-badge]: https://img.shields.io/librariesio/release/npm/%40alessiofrittoli%2Fcrypto-signature
[deps-url]: https://libraries.io/npm/%40alessiofrittoli%2Fcrypto-signature

[sponsor-badge]: https://img.shields.io/static/v1?label=Fund%20this%20package&message=%E2%9D%A4&logo=GitHub&color=%23DB61A2
[sponsor-url]: https://github.com/sponsors/alessiofrittoli

## Lightweight TypeScript Signatures library

This documentation provides an overview of the Digital Signature module and demonstrates how to use its methods for creating and verifying digital signatures.

### Table of Contents

- [Getting started](#getting-started)
  - [Usage](#usage)
  - [Creating a Digital Signature](#creating-a-digital-signature)
  - [Verifying a Digital Signature](#verifying-a-digital-signature)
  - [Supported Algorithms](#supported-algorithms)
  - [Error Handling](#error-handling)
- [Development](#development)
  - [ESLint](#eslint)
  - [Jest](#jest)
- [Contributing](#contributing)
- [Security](#security)
- [Credits](#made-with-)

### Overview

The module supports multiple algorithms for signing and verifying data, including HMAC, RSA, RSASSA-PSS, DSA, EcDSA and EdDSA. It provides a synchronous interface for cryptographic operations using Node.js's crypto module and custom utility classes.

---

### Getting started

Run the following command to start using `crypto-signature` in your projects:

```bash
npm i @alessiofrittoli/crypto-signature
```

or using `pnpm`

```bash
pnpm i @alessiofrittoli/crypto-signature
```

---

#### Usage

##### Importing the Module

```ts
import { Signature } from '@alessiofrittoli/crypto-signature'
import type { Sign } from '@alessiofrittoli/crypto-signature'
// or
import type { Sign } from '@alessiofrittoli/crypto-signature/types'
```

---

#### Creating a Digital Signature

The `Signature.sign()` method generates a signature for a given data input using a specified algorithm and private key.

##### Parameters

| Parameter   | Type                      | Default | Description             |
|-------------|---------------------------|---------|-------------------------|
| `data`      | `CoerceToUint8ArrayInput` | -       | The data to be signed.  |
| `key`       | `Sign.PrivateKey`         | -       | The private key used for signing. This can be a symmetric key, PEM private key or a key object. |
| `algorithm` | `Sign.AlgorithmJwkName`   | `HS256` | The JWK algorithm name. |

##### Returns

Type: `Buffer`

The generated signature Node.js Buffer.

##### Example

```ts
const data		= 'This is the data to sign'
const key		= crypto.createSecretKey( Buffer.from( 'your-secret-key' ) )
const algorithm	= 'HS256'

try {
    const signature = Signature.sign( data, key, algorithm )
    console.log( 'Generated Signature:', signature.toString( 'hex' ) )
} catch ( error ) {
    console.error( 'Error generating signature:', error )
}
```

#### Verifying a Digital Signature

The `Signature.isValid()` method verifies the integrity and authenticity of a digital signature.

##### Parameters

| Parameter   | Type                      | Default | Description                        |
|-------------|---------------------------|---------|------------------------------------|
| `signature` | `CoerceToUint8ArrayInput` | -       | The signature to verify.           |
| `data`      | `CoerceToUint8ArrayInput` | -       | The original data that was signed. |
| `key`       | `Sign.PublicKey`          | -       | The public key used for verification. This can be a symmetric key, PEM public key or a key object. |
| `algorithm` | `Sign.AlgorithmJwkName`   | `HS256` | The JWK algorithm name. |

##### Returns

Type: `true`

Returns `true` if the signature is valid. Throws an exception otherwise.

##### Example

```ts
const signature	= Buffer.from( 'signature-in-hex', 'hex' )
const data		= 'This is the data to verify'
const key		= crypto.createSecretKey( Buffer.from( 'your-secret-key' ) )
const algorithm	= 'HS256'

try {
    const isValid = Signature.isValid( signature, data, key, algorithm )
    console.log( 'Signature is valid:', isValid )
} catch ( error ) {
    console.error( 'Error verifying signature:', error )
}
```

#### Supported Algorithms

The module supports the following algorithms:

| Type         | JWK name | Description                                                        |
|--------------|----------|--------------------------------------------------------------------|
| `HMAC`       |          |                                                                    |
|              | `HS1`    | Signature generated/verified with `HMAC` key and `SHA-1`.          |
|              | `HS256`  | Signature generated/verified with `HMAC` key and `SHA-256`.        |
|              | `HS384`  | Signature generated/verified with `HMAC` key and `SHA-384`.        |
|              | `HS512`  | Signature generated/verified with `HMAC` key and `SHA-512`.        |
| `DSA`        |          |                                                                    |
|              | `DS1`    | Signature generated/verified with `DSA` keys and `SHA-1`.          |
|              | `DS256`  | Signature generated/verified with `DSA` keys and `SHA-256`.        |
|              | `DS384`  | Signature generated/verified with `DSA` keys and `SHA-384`.        |
|              | `DS512`  | Signature generated/verified with `DSA` keys and `SHA-512`.        |
| `EcDSA`      |          |                                                                    |
|              | `ES256`  | Signature generated/verified with `EC` keys and `SHA-256`.         |
|              | `ES384`  | Signature generated/verified with `EC` keys and `SHA-384`.         |
|              | `ES512`  | Signature generated/verified with `EC` keys and `SHA-512`.         |
| `EdDSA`      |          |                                                                    |
|              | `EdDSA`  | Signature generated/verified with `ed448` keys.                    |
|              | `EdDSA`  | Signature generated/verified with `ed25519` keys.                  |
| `RSA`        |          |                                                                    |
|              | `RS1`    | Signature generated/verified with `RSA` keys and `SHA-1`.          |
|              | `RS256`  | Signature generated/verified with `RSA` keys and `SHA-256`.        |
|              | `RS384`  | Signature generated/verified with `RSA` keys and `SHA-384`.        |
|              | `RS512`  | Signature generated/verified with `RSA` keys and `SHA-512`.        |
| `RSASSA-PSS` |          |                                                                    |
|              | `PS256`  | Signature generated/verified with `RSASSA-PSS` keys and `SHA-256`. |
|              | `PS384`  | Signature generated/verified with `RSASSA-PSS` keys and `SHA-384`. |
|              | `PS512`  | Signature generated/verified with `RSASSA-PSS` keys and `SHA-512`. |

---

### Error handling

This module throws a new `Exception` when an error occures providing an error code that will help in error handling.

The `ErrorCode` enumerator can be used to handle different errors with ease.

<details>

<summary>`ErrorCode` enum</summary>

| Constant              | Description                                              |
|-----------------------|----------------------------------------------------------|
| `UNKNOWN`             | Thrown when: |
|                       | - `Signature.sign()` encounters an unexpected error while creating a signature (mostly due to unsupported routine). The original thrown error is being reported in the `Exception.cause` property. |
|                       | - `Signature.isValid()` encounters an unexpected error while verifying a signature (mostly due to unsupported routine). The original thrown error is being reported in the `Exception.cause` property. |
| `EMPTY_VALUE`         | Thrown when: |
|                       | `Signature.sign()` has no `data` to sign. |
|                       | `Signature.isValid()` has no `data` to verify. |
| `INVALID_SIGN`        | Thrown when `Signature.isValid()` encounter an invalid signature (altered data, altered signature, wrong PublicKey). |
| `NO_SIGN`             | Thrown when `Signature.isValid()` has no `signature` to verify. |
| `NO_PRIVATEKEY`       | Thrown when `Signature.sign()` has no Private Key to sign with. |
| `NO_PUBLICKEY`        | Thrown when `Signature.isValid()` has no Public Key to verify the signature with. |

</details>

---

<details>

<summary>Example usage</summary>

```ts
import { Exception } from '@alessiofrittoli/exception'
import { Signature } from '@alessiofrittoli/crypto-signature'
import { ErrorCode } from '@alessiofrittoli/crypto-signature/error'

try {
    Signature.isValid( 'invalid signature', 'Data', 'myscretkey' )
} catch ( error ) {
    console.log( error )
    // safe type guard the `error` variable.
    if ( Exception.isException<string, ErrorCode>( error ) ) {
        // ... do somethign with `error.code`
        if ( error.code === ErrorCode.Signature.INVALID_SIGN ) {
            // ...
        }
    }
}
```

</details>

---

This documentation covers the essential functionality of the module, allowing users to securely sign and verify data using various cryptographic algorithms.

---

### Development

#### Install depenendencies

```bash
npm install
```

or using `pnpm`

```bash
pnpm i
```

#### Build the source code

Run the following command to test and build code for distribution.

```bash
pnpm build
```

#### [ESLint](https://www.npmjs.com/package/eslint)

warnings / errors check.

```bash
pnpm lint
```

#### [Jest](https://npmjs.com/package/jest)

Run all the defined test suites by running the following:

```bash
# Run tests and watch file changes.
pnpm test:watch

# Run tests in a CI environment.
pnpm test:ci
```

You can eventually run specific suits like so:

- See [`package.json`](./package.json) file scripts for more info.

```bash
pnpm test:jest
```

Run tests with coverage.

An HTTP server is then started to serve coverage files from `./coverage` folder.

⚠️ You may see a blank page the first time you run this command. Simply refresh the browser to see the updates.

```bash
test:coverage:serve
```

---

### Contributing

Contributions are truly welcome!

Please refer to the [Contributing Doc](./CONTRIBUTING.md) for more information on how to start contributing to this project.

Help keep this project up to date with [GitHub Sponsor][sponsor-url].

[![GitHub Sponsor][sponsor-badge]][sponsor-url]

---

### Security

If you believe you have found a security vulnerability, we encourage you to **_responsibly disclose this and NOT open a public issue_**. We will investigate all legitimate reports. Email `security@alessiofrittoli.it` to disclose any security vulnerabilities.

### Made with ☕

<table style='display:flex;gap:20px;'>
  <tbody>
    <tr>
      <td>
        <img alt="avatar" src='https://avatars.githubusercontent.com/u/35973186' style='width:60px;border-radius:50%;object-fit:contain;'>
      </td>
      <td>
        <table style='display:flex;gap:2px;flex-direction:column;'>
          <tbody>
              <tr>
                <td>
                  <a href='https://github.com/alessiofrittoli' target='_blank' rel='noopener'>Alessio Frittoli</a>
                </td>
              </tr>
              <tr>
                <td>
                  <small>
                    <a href='https://alessiofrittoli.it' target='_blank' rel='noopener'>https://alessiofrittoli.it</a> |
                    <a href='mailto:info@alessiofrittoli.it' target='_blank' rel='noopener'>info@alessiofrittoli.it</a>
                  </small>
                </td>
              </tr>
          </tbody>
        </table>
      </td>
    </tr>
  </tbody>
</table>
