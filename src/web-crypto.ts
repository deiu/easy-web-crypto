/**
 * Originally from https://github.com/QwantResearch/masq-common/ 
 * with improvements by Andrei Sambra
 */

import { Buffer } from 'buffer';

interface CipherData {
  ciphertext: string;
  iv: string;
}

interface DerivationParams {
  salt: string;
  iterations: number;
  hashAlgo: string;
}

interface ProtectedMasterKey {
  derivationParams: DerivationParams;
  encryptedMasterKey: CipherData;
}

const checkCryptokey = (key: CryptoKey) => {
  if (!key.type || key.type !== 'secret') {
    throw new Error('Invalid key type')
  }
}

const genRandomBuffer = (len = 16) => {
  const values = globalThis.crypto.getRandomValues(new Uint8Array(len))
  return Buffer.from(values)
}

const genRandomBufferAsStr = (len = 16, encodingFormat: BufferEncoding = 'hex') => {
  if (encodingFormat) {
    checkEncodingFormat(encodingFormat)
  }
  const buf = genRandomBuffer(len)
  return buf.toString(encodingFormat)
}

const checkPassphrase = (str: string) => {
  if (typeof str !== 'string' || str === '') {
    throw new Error(`Not a valid value`)
  }
}

const checkEncodingFormat = (format: BufferEncoding) => {
  if (format !== 'hex' && format !== 'base64') throw new Error('Invalid encoding')
}

/**
 * Generate a random hexadecimal ID of a given length
 *
 * @param {integer} [len] The string length of the new ID
 * @returns {string} The new ID
 */
const genId = (len = 32) => {
  // 2 bytes for each char
  return genRandomBufferAsStr(Math.floor(len / 2))
}

/**
 * Generate the hash of a string or ArrayBuffer
 *
 * @param {string | arrayBuffer} data The message
 * @param {string} [format] The encoding format ('hex' by default, can also be 'base64')
 * @param {string} [name] The hashing algorithm (SHA-256 by default)
 * @returns {Promise<String>}  A promise that contains the hash as a String encoded with encodingFormat
 */
const hash = async (data: string | ArrayBuffer, format: BufferEncoding = 'hex', name = 'SHA-256') => {
  const digest = await globalThis.crypto.subtle.digest(
    {
      name
    },
    ((typeof data === 'string') ? Buffer.from(data) : data) as BufferSource
  )
  return Buffer.from(digest).toString(format)
}

/**
   * Generate an ECDA key pair based on the provided curve name
   *
   * @param {boolean} extractable - Specify if the generated key is extractable
   * @param {namedCurve} namedCurve - The curve name to use
   * @returns {Promise<CryptoKey>} - A promise containing the key pair
   */
const genKeyPair = (extractable = true, namedCurve = 'P-256') => {
  return globalThis.crypto.subtle.generateKey(
    {
      name: 'ECDSA',
      namedCurve // can be "P-256", "P-384", or "P-521"
    },
    extractable,
    ['sign', 'verify']
  )
}

// Helper to correctly select return type based on format argument.
type KeyBufferEncoding = BufferEncoding | 'raw';
type SelectKeyType<TFormat extends KeyBufferEncoding> = TFormat extends 'raw' ? Uint8Array : string;
// a distributive conditional, not overloads: a union argument keeps resolving
// to the union return type it resolved to before
// the three formats that predate jwk, kept as their own type so the generic
// overload instantiates at exactly the constraint it had before
type KeyExportFormat = 'pkcs8' | 'spki' | 'raw';
type SelectExportedKey<TType extends KeyExportFormat> = TType extends 'raw' ? Uint8Array<ArrayBuffer> : ArrayBuffer;

/**
  * Import a public key
  *
  * @param {CryptoKey} key - The public CryptoKey
  * @param {string} namedCurve - The curve name to use
  * @returns {Promise<arrayBuffer>} - The raw key
  */
function importPublicKey(key: string): Promise<CryptoKey>;
function importPublicKey(key: string, namedCurve: string): Promise<CryptoKey>;
function importPublicKey<TFormat extends KeyBufferEncoding>(key: SelectKeyType<TFormat>, namedCurve: string, format: TFormat): Promise<CryptoKey>;

function importPublicKey(key: string | Uint8Array, namedCurve = 'P-256', format: KeyBufferEncoding = 'base64') {
  const keyData = typeof key === 'string' ? Buffer.from(key, format as BufferEncoding) : key;
  return globalThis.crypto.subtle.importKey(
    'spki',
    keyData as BufferSource,
    {
      name: 'ECDSA',
      namedCurve // can be "P-256", "P-384", or "P-521"
    },
    true,
    ['verify']
  )
}

/**
  * Import a private key
  *
  * @param {CryptoKey} key - The private CryptoKey
  * @param {string} namedCurve - The curve name to use
  * @returns {Promise<arrayBuffer>} - The raw key
  */
function importPrivateKey(key: string): Promise<CryptoKey>;
function importPrivateKey(key: string, namedCurve: string): Promise<CryptoKey>;
function importPrivateKey<TFormat extends KeyBufferEncoding>(key: SelectKeyType<TFormat>, namedCurve: string, format: TFormat): Promise<CryptoKey>;

function importPrivateKey(key: string | Uint8Array, namedCurve = 'P-256', format: KeyBufferEncoding = 'base64') {
  const keyData = typeof key === 'string' ? Buffer.from(key, format as BufferEncoding) : key;
  return globalThis.crypto.subtle.importKey(
    'pkcs8',
    keyData as BufferSource,
    {
      name: 'ECDSA',
      namedCurve // can be "P-256", "P-384", or "P-521"
    },
    true,
    ['sign']
  )
}

/**
  * Export a public key
  *
  * @param {CryptoKey} key - The public CryptoKey
  * @param {string} format - The format to use for export
  * @returns {Promise<string|Uint8Array>} - The exported key
  */
function exportPublicKey(key: CryptoKey): Promise<string>;
function exportPublicKey<TFormat extends KeyBufferEncoding = 'base64'>(key: CryptoKey, format?: TFormat): Promise<SelectKeyType<TFormat>>;

async function exportPublicKey(key: CryptoKey, format: KeyBufferEncoding = 'base64') {
  const exported = await globalThis.crypto.subtle.exportKey('spki', key)
  if (format === 'raw') {
    return new Uint8Array(exported)
  }
  return Buffer.from(exported).toString(format as BufferEncoding)
}

/**
  * Export a private key
  *
  * @param {CryptoKey} key - The private CryptoKey
  * @param {string} format - The format to use for export
  * @returns {Promise<string|Uint8Array>} - The exported key
  */
function exportPrivateKey(key: CryptoKey): Promise<string>;
function exportPrivateKey<TFormat extends KeyBufferEncoding = 'base64'>(key: CryptoKey, format?: TFormat): Promise<SelectKeyType<TFormat>>;

async function exportPrivateKey(key: CryptoKey, format: KeyBufferEncoding = 'base64') {
  const exported = await globalThis.crypto.subtle.exportKey('pkcs8', key)
  if (format === 'raw') {
    return new Uint8Array(exported)
  }
  return Buffer.from(exported).toString(format as BufferEncoding)
}

/**
 * Sign data using the private key
 *
 * @param {CryptoKey} key - The private key
 * @param {*} data - Data to sign
 * @param {string} format - The format of the returned signature
 * @param {string} hash - The hashing algorithm
 * @returns {Promise<string|Uint8Array>} - The signature
 */
function sign(key: CryptoKey, data: any): Promise<string>;
function sign<TFormat extends KeyBufferEncoding = 'base64'>(key: CryptoKey, data: any, format?: TFormat, hash?: string): Promise<SelectKeyType<TFormat>>;

async function sign(key: CryptoKey, data: any, format: KeyBufferEncoding = 'base64', hash = 'SHA-256') {
  const signature = await globalThis.crypto.subtle.sign(
    {
      name: 'ECDSA',
      hash: { name: hash } // can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
    },
    key,
    Buffer.from(typeof data === "string" ? data : JSON.stringify(data))
  )
  if (format === 'raw') {
    return new Uint8Array(signature)
  }
  return Buffer.from(signature).toString(format as BufferEncoding)
}

/**
 * Verify data using the public key
 *
 * @param {CryptoKey} key - The public key
 * @param {*} data - Data to verify
 * @param {*} hash - The hashing algorithm
 * @returns {Promise<boolean>} - The verification outcome
 */
function verify(key: CryptoKey, data: any, signature: string, format?: BufferEncoding, hash?: string): Promise<boolean>;
function verify(key: CryptoKey, data: any, signature: Uint8Array, format?: KeyBufferEncoding, hash?: string): Promise<boolean>;

async function verify(key: CryptoKey, data: any, signature: string | Uint8Array, format: KeyBufferEncoding = 'base64', hash = 'SHA-256') {
  return globalThis.crypto.subtle.verify(
    {
      name: 'ECDSA',
      hash: { name: hash } // can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
    },
    key,
    (typeof signature === 'string' ? Buffer.from(signature, format as BufferEncoding) : Buffer.from(signature)) as BufferSource,
    Buffer.from(typeof data === "string" ? data : JSON.stringify(data)) as BufferSource
  )
}

/**
   * Generate an AES key based on the cipher mode and keysize
   *
   * @param {boolean} [extractable] - Specify if the generated key is extractable
   * @param {string} [mode] - The aes mode of the generated key
   * @param {Number} [keySize] - Specify if the generated key is extractable
   * @returns {Promise<CryptoKey>} - The generated AES key.
   */
const genAESKey = (extractable = true, mode = 'AES-GCM', keySize = 128) => {
  return globalThis.crypto.subtle.generateKey({
    name: mode,
    length: keySize
  },
  extractable,
  ['decrypt', 'encrypt'])
}

/**
    * Import a raw|jwk as a CryptoKey
    *
    * @param {arrayBuffer|Object} key - The key
    * @param {string} [type] - The type of the key to import ('raw', 'jwk')
    * @param {string} [mode] - The mode of the key to import (default 'AES-GCM')
    * @returns {Promise<arrayBuffer>} - The cryptoKey
    */
function importKey(key: ArrayBuffer | Uint8Array | Buffer, type?: 'pkcs8' | 'spki' | 'raw', mode?: string): Promise<CryptoKey>;
function importKey(key: JsonWebKey, type: 'jwk', mode?: string): Promise<CryptoKey>;

function importKey(key: ArrayBuffer | Uint8Array | Buffer | JsonWebKey, type: KeyFormat = 'raw', mode = 'AES-GCM') {
  const parsedKey = (type === 'raw') ? Buffer.from(key as unknown as string, 'base64') : key
  return (type === 'jwk')
    ? globalThis.crypto.subtle.importKey('jwk', parsedKey as JsonWebKey, { name: mode }
      , true, ['encrypt', 'decrypt'])
    : globalThis.crypto.subtle.importKey(type, parsedKey as BufferSource, { name: mode }
      , true, ['encrypt', 'decrypt'])
}

/**
  * Export a CryptoKey into a raw|jwk key
  *
  * @param {CryptoKey} key - The CryptoKey
  * @param {string} [type] - The type of the exported key: raw|jwk
  * @returns {Promise<arrayBuffer>} - The raw key or the key as a jwk format
  */
function exportKey(key: CryptoKey, type: 'jwk'): Promise<JsonWebKey>;
function exportKey<TType extends KeyExportFormat = 'raw'>(key: CryptoKey, type?: TType): Promise<SelectExportedKey<TType>>;

async function exportKey(key: CryptoKey, type: KeyFormat = 'raw') {
  const exportedKey = await globalThis.crypto.subtle.exportKey(type, key)
  return (type === 'raw') ? new Uint8Array(exportedKey as ArrayBuffer) : exportedKey
}

/**
   * Encrypt buffer
   *
   * @param {ArrayBuffer} key - The AES CryptoKey
   * @param {ArrayBuffer} data - Data to encrypt
   * @param {Object} cipherContext - The AES cipher parameters
   * @returns {ArrayBuffer} - The encrypted buffer
   */
const encryptBuffer = async <TCipherContext extends Algorithm>(key: CryptoKey, data: Buffer | Uint8Array, cipherContext: TCipherContext) => {
  const encrypted = await globalThis.crypto.subtle.encrypt(cipherContext, key, data as BufferSource)
  return new Uint8Array(encrypted)
}

/**
 * Decrypt buffer
 * @param {ArrayBuffer} key - The AES CryptoKey
 * @param {ArrayBuffer} data - Data to decrypt
 * @param {Object} cipherContext - The AES cipher parameters
 * @returns {Promise<ArrayBuffer>} - The decrypted buffer
 */
const decryptBuffer = async <TCipherContext extends Algorithm>(key: CryptoKey, data: ArrayBuffer | Buffer | Uint8Array, cipherContext: TCipherContext) => {
  // TODO: test input params
  try {
    const decrypted = await globalThis.crypto.subtle.decrypt(cipherContext, key, data as BufferSource)
    return new Uint8Array(decrypted)
  } catch (e) {
    if (e instanceof Error && e.message === 'Unsupported state or unable to authenticate data') {
      throw new Error('Unable to decrypt data')
    } else if (typeof e === 'string') {
      throw new Error(e);
    }
  }
}

/**
 * Encrypt data
 *
 * @param {CryptoKey} key - The AES CryptoKey
 * @param {string | Object} - The data to encrypt
 * @param {string} [format] - The ciphertext and iv encoding format
 * @returns {Object} - The stringified ciphertext object (ciphertext and iv)
 */
const encrypt = async (key: CryptoKey, data: string | object, format: BufferEncoding = 'hex'): Promise<CipherData> => {
  checkCryptokey(key)
  const context = {
    iv: genRandomBuffer(key.algorithm.name === 'AES-GCM' ? 12 : 16),
    plaintext: Buffer.from(JSON.stringify(data))
  }

  // Prepare cipher context, depends on cipher mode
  const cipherContext = {
    name: key.algorithm.name,
    iv: context.iv
  }

  const encrypted = await encryptBuffer(key, context.plaintext, cipherContext)
  return {
    ciphertext: Buffer.from(encrypted).toString(format),
    iv: Buffer.from(context.iv).toString(format)
  }
}

/**
   * Decrypt data
   *
   * @param {CryptoKey} key - The AES CryptoKey
   * @param {string | Object} - The data to decrypt
   * @param {string} [format] - The ciphertext and iv encoding format
   */
const decrypt = async (key: CryptoKey, ciphertext: CipherData, format: BufferEncoding = 'hex') => {
  checkCryptokey(key)

  const context = {
    ciphertext: Buffer.from(Object.prototype.hasOwnProperty.call(ciphertext, 'ciphertext') ? ciphertext.ciphertext : '', (format)),
    // IV is 128 bits long === 16 bytes
    iv: Object.prototype.hasOwnProperty.call(ciphertext, 'iv') ? Buffer.from(ciphertext.iv, (format)) : ''
  }

  // Prepare cipher context, depends on cipher mode
  const cipherContext = {
    name: key.algorithm.name,
    iv: context.iv
  }
  try {
    const decrypted = await decryptBuffer(key, context.ciphertext, cipherContext)
    if (decrypted === undefined) {
      throw new Error();
    }
    return JSON.parse(Buffer.from(decrypted).toString())
  } catch (error) {
    throw new Error('Unable to decrypt data')
  }
}

/**
 * Generate a PBKDF2 derived key (bits) based on user given passPhrase
 *
 * @param {string | arrayBuffer} passPhrase The passphrase that is used to derive the key
 * @param {arrayBuffer} [salt] The salt
 * @param {Number} [iterations] The iterations number
 * @param {string} [hashAlgo] The hash function used for derivation
 * @returns {Promise<Uint8Array>} A promise that contains the derived key
 */
const deriveBits = async (passPhrase: string | ArrayBuffer | Uint8Array, salt: ArrayBuffer | Uint8Array, iterations: number, hashAlgo: string) => {
  // Always specify a strong salt
  if (iterations < 10000) { console.warn('Less than 10000 :(') }

  const baseKey = await globalThis.crypto.subtle.importKey(
    'raw',
    ((typeof passPhrase === 'string') ? Buffer.from(passPhrase) : passPhrase) as BufferSource,
    'PBKDF2',
    false,
    ['deriveBits', 'deriveKey']
  )
  const derivedKey = await globalThis.crypto.subtle.deriveBits({
    name: 'PBKDF2',
    salt: (salt || new Uint8Array([])) as BufferSource,
    iterations: iterations || 100000,
    hash: hashAlgo || 'SHA-256'
  }, baseKey, 128)

  return new Uint8Array(derivedKey)
}

/**
 * Derive a key based on a given passphrase
 *
 * @param {string} passPhrase The passphrase that is used to derive the key
 * @param {arrayBuffer} [salt] The salt
 * @param {Number} [iterations] The iterations number
 * @param {string} [hashAlgo] The hash function used for derivation and final hash computing
 * @returns {Promise<keyEncryptionKey>} A promise that contains the derived key and derivation
 * parameters
 */
const deriveKeyFromPassphrase = async (passPhrase: string, salt: Uint8Array | Buffer = genRandomBuffer(16), iterations = 100000, hashAlgo: string = 'SHA-256') => {
  checkPassphrase(passPhrase)

  const derivedKey = await deriveBits(passPhrase, salt as Uint8Array, iterations, hashAlgo)
  const key = await importKey(derivedKey)
  return {
    derivationParams: {
      salt: Buffer.from(salt).toString('hex'),
      iterations,
      hashAlgo
    },
    key
  }
}

/**
 * Derive the passphrase with PBKDF2 to obtain a KEK
 * Generate a AES key (masterKey)
 * Encrypt the masterKey with the KEK
 *
 * @param {string} passPhrase The passphrase that is used to derive the key
 * @param {arrayBuffer} [salt] The salt
 * @param {Number} [iterations] The iterations number
 * @param {string} [hashAlgo] The hash function used for derivation and final hash computing
 * @returns {Promise<protectedMasterKey>} A promise that contains the encrypted derived key
 */
const genEncryptedMasterKey = async (passPhrase: string, salt?: Buffer | Uint8Array, iterations?: number, hashAlgo?: string): Promise<ProtectedMasterKey> => {
  // derive key encryption key from passphrase
  const keyEncryptionKey = await deriveKeyFromPassphrase(passPhrase, salt, iterations, hashAlgo)

  // Generate the masterKey
  const masterKey = genRandomBufferAsStr(32, 'hex')

  const encryptedMasterKey = await encrypt(keyEncryptionKey.key, masterKey)

  return {
    derivationParams: keyEncryptionKey.derivationParams,
    encryptedMasterKey
  }
}

/**
 * Update the derived encryption key (KEK) based on the new passphrase from user, while retaining
 * the symmetric key that encrypts data at rest
 *
 * @param {string} currentPassPhrase The current (old) passphrase that is used to derive the key
 * @param {string} newPassPhrase The new passphrase that will be used to derive the key
 * @param {oldMasterKey} oldMasterKey - The old object returned by genEncryptedMasterKey for the old passphrase
 * @param {arrayBuffer} [salt] The salt
 * @param {Number} [iterations] The iterations number
 * @param {string} [hashAlgo] The hash function used for derivation and final hash computing
 * @returns {Promise<protectedMasterKey>}
 */
const updatePassphraseKey = async (currentPassPhrase: string, newPassPhrase: string, oldMasterKey: ProtectedMasterKey, salt?: Buffer | Uint8Array, iterations?: number, hashAlgo?: string): Promise<ProtectedMasterKey> => {
  const masterKey = await decryptMasterKey(currentPassPhrase, oldMasterKey)
  // derive a new key encryption key from newPassPhrase
  const keyEncryptionKey = await deriveKeyFromPassphrase(newPassPhrase, salt, iterations, hashAlgo)

  // enconde existing masterKey as a hex string since it's a buffer
  const rawExport = await exportKey(masterKey);
  const toBeEncryptedMasterKey = Buffer.from(rawExport as Uint8Array).toString('hex')

  const encryptedMasterKey = await encrypt(keyEncryptionKey.key, toBeEncryptedMasterKey)

  return {
    derivationParams: keyEncryptionKey.derivationParams,
    encryptedMasterKey
  }
}

/**
 * Decrypt a master key by deriving the encryption key from the
 * provided passphrase and encrypted master key.
 *
 * @param {string | arrayBuffer} passPhrase The passphrase that is used to derive the key
 * @param {protectedMasterKey} protectedMasterKey - The same object returned
 * by genEncryptedMasterKey
 * @returns {Promise<masterKey>} A promise that contains the masterKey
 */
const decryptMasterKey = async (passPhrase: string, protectedMasterKey: ProtectedMasterKey) => {
  if (!protectedMasterKey.encryptedMasterKey ||
    !protectedMasterKey.derivationParams) {
    throw new Error('Missing properties from master key')
  }
  const { derivationParams, encryptedMasterKey } = protectedMasterKey
  const { salt, iterations, hashAlgo } = derivationParams
  const _salt = typeof (salt) === 'string' ? Buffer.from(salt, ('hex')) : salt
  const derivedKey = await deriveBits(passPhrase, _salt as Uint8Array, iterations, hashAlgo)
  const keyEncryptionKey = await importKey(derivedKey)
  try {
    const decryptedMasterKeyHex = await decrypt(keyEncryptionKey, encryptedMasterKey)
    // return decryptedMasterKeyHex
    const parsedKey = Buffer.from(decryptedMasterKeyHex, 'hex')
    return globalThis.crypto.subtle.importKey('raw', parsedKey, { name: 'AES-GCM' }
      , true, ['encrypt', 'decrypt'])
  } catch (error) {
    throw new Error('Wrong passphrase')
  }
}

const _genRandomBuffer = genRandomBuffer;
const _genRandomBufferAsStr = genRandomBufferAsStr;

export {
  genId,
  hash,
  genKeyPair,
  importPublicKey,
  importPrivateKey,
  exportPublicKey,
  exportPrivateKey,
  sign,
  verify,
  genAESKey,
  importKey,
  exportKey,
  encrypt,
  decrypt,
  encryptBuffer,
  decryptBuffer,
  genEncryptedMasterKey,
  decryptMasterKey,
  updatePassphraseKey,
  _genRandomBuffer,
  _genRandomBufferAsStr,
  CipherData,
  DerivationParams,
  ProtectedMasterKey
}
