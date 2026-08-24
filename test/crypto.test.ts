import { describe, it, expect, assert, vi } from 'vitest';
import * as WebCrypto from '../src/web-crypto';

describe('Web crypto', function () {
  describe('Generating a random buffer (for iv)', () => {
    it('Should generate a random buffer without providing the length parameter', () => {
      const iv1 = WebCrypto._genRandomBuffer();
      assert.lengthOf(iv1, 16);
    });

    it('Should generate a random buffer with a specific length parameter', () => {
      const iv2 = WebCrypto._genRandomBuffer(8);
      assert.lengthOf(iv2, 8);
    });
    it('Should generate a random buffer with a specific length parameter in hex format', () => {
      const buf1 = WebCrypto._genRandomBufferAsStr(8, 'hex');
      assert.lengthOf(buf1, 16);
    });
    it('Should generate a random buffer with a specific length parameter in base64 format', () => {
      const buf = WebCrypto._genRandomBufferAsStr(8, 'base64');
      assert.lengthOf(buf, 12);
    });
    it('Should reject if a wrong encoding format is given', async () => {
      let err: any;
      try {
        await WebCrypto._genRandomBufferAsStr(8, 'base777' as any);
      } catch (error) {
        err = error;
      }
      assert.equal(err.message, 'Invalid encoding');
    });
  });

  describe('Generating a random ID', () => {
    it('Should generate a random identifier without providing the length parameter', () => {
      const id = WebCrypto.genId(32);
      assert.lengthOf(id, 32);
    });

    it('Should generate a random identifier with a specific length parameter of 16', () => {
      const id = WebCrypto.genId(16);
      assert.lengthOf(id, 16);
    });
  });

  describe('Hashing functions', () => {
    const toHash = 'abc123';
    it('Should generate a SHA-256 hash from a string using no parameters (default)', async () => {
      const hashed = await WebCrypto.hash(toHash);
      assert.lengthOf(hashed, 64);
    });

    it('Should generate a SHA-256 hash from an ArrayBuffer using no parameters (default)', async () => {
      const buffer = new ArrayBuffer(16);
      const hashed = await WebCrypto.hash(buffer);
      assert.lengthOf(hashed, 64);
    });

    it('Should generate a SHA-1 hash when specifying hex format', async () => {
      const hashed = await WebCrypto.hash(toHash, 'hex', 'SHA-1');
      assert.lengthOf(hashed, 40);
    });

    it('Should generate a SHA-256 hash when specifying hex format', async () => {
      const hashed = await WebCrypto.hash(toHash, 'hex');
      assert.lengthOf(hashed, 64);
    });

    it('Should generate a SHA-384 hash when specifying hex format', async () => {
      const hashed = await WebCrypto.hash(toHash, 'hex', 'SHA-384');
      assert.lengthOf(hashed, 96);
    });

    it('Should generate a SHA-512 hash when specifying hex format', async () => {
      const hashed = await WebCrypto.hash(toHash, 'hex', 'SHA-512');
      assert.lengthOf(hashed, 128);
    });

    it('Should generate a SHA-1 hash when specifying base64 format', async () => {
      const hashed = await WebCrypto.hash(toHash, 'base64', 'SHA-1');
      assert.lengthOf(hashed, 28);
    });

    it('Should generate a SHA-256 hash when specifying base64 format', async () => {
      const hashed = await WebCrypto.hash(toHash, 'base64', 'SHA-256');
      assert.lengthOf(hashed, 44);
    });

    it('Should generate a SHA-384 hash when specifying base64 format', async () => {
      const hashed = await WebCrypto.hash(toHash, 'base64', 'SHA-384');
      assert.lengthOf(hashed, 64);
    });

    it('Should generate a SHA-256 hash when specifying base64 format', async () => {
      const hashed = await WebCrypto.hash(toHash, 'base64', 'SHA-512');
      assert.lengthOf(hashed, 88);
    });
  });

  describe('ECDA keys', () => {
    it('Should fail to generate a key pair with wrong parameters', async () => {
      let err: any;
      try {
        await WebCrypto.genKeyPair('foo' as any, 'baz' as any);
      } catch (error) {
        err = error;
      }
      expect(err.message).to.contain('Unrecognized namedCurve');

      try {
        await WebCrypto.genKeyPair(undefined, 'P-256' as any);
      } catch (error) {
        err = error;
      }
      expect(err.message).to.contain('Unrecognized namedCurve');
    });

    it('Should generate an extractable key pair with default parameters', async () => {
      let err: any;
      let keypair: any;
      try {
        keypair = await WebCrypto.genKeyPair();
      } catch (error) {
        err = error;
      }
      assert.isUndefined(err);
      assert.isDefined(keypair);
      assert.isTrue(keypair.publicKey.extractable);
      assert.isTrue(keypair.privateKey.extractable);
    });

    it('Should generate a key pair with unextractable private key using false for extractable and default for namedCurve as parameters', async () => {
      let err: any;
      let keypair: any;
      try {
        keypair = await WebCrypto.genKeyPair(false);
      } catch (error) {
        err = error;
      }
      assert.isUndefined(err);
      assert.isDefined(keypair);
      assert.isTrue(keypair.publicKey.extractable);
      assert.isFalse(keypair.privateKey.extractable);
    });

    it('Should fail to export a public key with wrong parameters', async () => {
      let err: any;
      try {
        await (WebCrypto as any).exportPublicKey();
      } catch (error) {
        err = error;
      }
      assert.exists(err?.message, 'Failed to execute');

      err = undefined;
      try {
        await (WebCrypto as any).exportPublicKey('foo');
      } catch (error) {
        err = error;
      }
      assert.isDefined(err?.message, 'Failed to execute');
    });

    it('Should export a public key in base64 format by default', async () => {
      const keys = await WebCrypto.genKeyPair();
      const exported = await WebCrypto.exportPublicKey(keys.publicKey);
      assert.isDefined(exported);
      assert.typeOf(exported, 'string');
    });

    it('Should export a public key in raw format', async () => {
      const keys = await WebCrypto.genKeyPair();
      const exported = await WebCrypto.exportPublicKey(keys.publicKey, 'raw');

      assert.isDefined(exported);
      assert.typeOf(exported, 'Uint8Array');
    });

    it('Should fail to import a public key with wrong parameters', async () => {
      let err: any;
      try {
        await WebCrypto.importPublicKey('foo', 'baz' as any);
      } catch (error) {
        err = error;
      }
      expect(err.message).to.contain('Unrecognized namedCurve');

      try {
        await WebCrypto.importPublicKey(undefined as any, 'P-256');
      } catch (error) {
        err = error;
      }
      assert.exists(err.message, 'First argument must be a string');
    });

    it('Should import a public key for curves P-256, P-384, P-521', async () => {
      const curves: Array<'P-256' | 'P-384' | 'P-521'> = ['P-256', 'P-384', 'P-521'];
      // default params
      const keys = await WebCrypto.genKeyPair();
      const exported = await WebCrypto.exportPublicKey(keys.publicKey);
      const imported = await WebCrypto.importPublicKey(exported as string);
      assert.typeOf(imported, 'CryptoKey');

      for (const curve of curves) {
        let err: any;
        try {
          const k = await WebCrypto.genKeyPair(true, curve);
          const exp = await WebCrypto.exportPublicKey(k.publicKey);
          const imp = await WebCrypto.importPublicKey(exp as string, curve);
          assert.typeOf(imp, 'CryptoKey');
        } catch (error) {
          err = error;
        }
        assert.isUndefined(err);
      }
    });

    it('Should fail to export a private key with wrong parameters', async () => {
      let err: any;
      try {
        await (WebCrypto as any).exportPrivateKey();
      } catch (error) {
        err = error;
      }
      assert.exists(err?.message, 'Failed to execute');

      err = undefined;
      try {
        await (WebCrypto as any).exportPrivateKey('foo');
      } catch (error) {
        err = error;
      }
      assert.isDefined(err?.message, 'Failed to execute');
    });

    it('Should export a public key to base64 format by default', async () => {
      const keys = await WebCrypto.genKeyPair();
      const exported = await WebCrypto.exportPrivateKey(keys.privateKey);

      assert.typeOf(exported, 'string');
    });

    it('Should export a public key to raw format', async () => {
      const keys = await WebCrypto.genKeyPair();
      const exported = await WebCrypto.exportPrivateKey(keys.privateKey, 'raw');

      assert.typeOf(exported, 'Uint8Array');
    });

    it('Should fail to import a private key with wrong parameters', async () => {
      let err: any;
      try {
        await WebCrypto.importPrivateKey('foo', 'baz' as any);
      } catch (error) {
        err = error;
      }
      expect(err.message).to.contain('Unrecognized namedCurve');

      try {
        await WebCrypto.importPrivateKey(undefined as any, 'P-256');
      } catch (error) {
        err = error;
      }
      assert.exists(err.message, 'First argument must be a string');
    });

    it('Should import a private key for curves P-256, P-384, P-521', async () => {
      const curves: Array<'P-256' | 'P-384' | 'P-521'> = ['P-256', 'P-384', 'P-521'];
      // default params
      const keys = await WebCrypto.genKeyPair();
      const exported = await WebCrypto.exportPrivateKey(keys.privateKey);
      const imported = await WebCrypto.importPrivateKey(exported as string);
      assert.typeOf(imported, 'CryptoKey');

      for (const curve of curves) {
        let err: any;
        try {
          const k = await WebCrypto.genKeyPair(true, curve);
          const exp = await WebCrypto.exportPrivateKey(k.privateKey);
          const imp = await WebCrypto.importPrivateKey(exp as string, curve);
          assert.typeOf(imp, 'CryptoKey');
        } catch (error) {
          err = error;
        }
        assert.isUndefined(err);
      }
    });

    it('Should fail to sign with wrong parameters', async () => {
      const keys = await WebCrypto.genKeyPair();

      let err: any;
      try {
        await (WebCrypto as any).sign();
      } catch (error) {
        err = error;
      }
      assert.exists(err?.message, 'First argument must be a string');

      try {
        await (WebCrypto as any).sign(keys.privateKey, 'foo', 'bar');
      } catch (error) {
        err = error;
      }
      assert.exists(err?.message, 'First argument must be a string');
    });

    it('Should sign/verify data using base64 as default format for signatures', async () => {
      const data = { foo: 'bar' };
      const keys = await WebCrypto.genKeyPair();

      const sig = await WebCrypto.sign(keys.privateKey, data);
      const valid = await WebCrypto.verify(keys.publicKey, data, sig);
      assert.isTrue(valid);
    });

    it('Should sign/verify data using base64 as default format for signatures with a data string', async () => {
      const data = 'foobar';
      const keys = await WebCrypto.genKeyPair();

      const sig = await WebCrypto.sign(keys.privateKey, data);
      const valid = await WebCrypto.verify(keys.publicKey, data, sig);
      assert.isTrue(valid);
    });

    it('Should sign/verify data using raw format for signatures', async () => {
      const data = { foo: 'bar' };
      const keys = await WebCrypto.genKeyPair();

      const sig = await WebCrypto.sign(keys.privateKey, data, 'raw');
      const valid = await WebCrypto.verify(keys.publicKey, data, sig, 'raw');
      assert.isTrue(valid);
    });

    it('Should sign/verify data using raw format for signatures with a data string', async () => {
      const data = 'foobar';
      const keys = await WebCrypto.genKeyPair();

      const sig = await WebCrypto.sign(keys.privateKey, data, 'raw');
      const valid = await WebCrypto.verify(keys.publicKey, data, sig, 'raw');
      assert.isTrue(valid);
    });
  });

  describe('AES keys', () => {
    it('Should reject if the key is not of type CryptoKey', async () => {
      let err: any;
      try {
        await WebCrypto.encrypt([2, 3] as any, { data: 'hello' });
      } catch (error) {
        err = error;
      }
      assert.equal(err.message, 'Invalid key type');
    });

    it('Should fail to decrypt a message with default parameters (wrong iv)', async () => {
      const message = { data: 'hello' };
      const key = await WebCrypto.genAESKey();
      const ciphertext = await WebCrypto.encrypt(key, message);

      let err: any = { message: '_ERROR_NOT_THROWN_' };
      try {
        ciphertext.iv = ciphertext.iv.slice(0, 10);
        await WebCrypto.decrypt(key, ciphertext);
      } catch (error) {
        err = error;
      }
      assert.equal(err.message, 'Unable to decrypt data');
    });

    it('Should fail to decrypt a message with default parameters (wrong key)', async () => {
      const message = { data: 'hello' };
      const key = await WebCrypto.genAESKey();
      const ciphertext = await WebCrypto.encrypt(key, message);

      let err: any;
      try {
        const key2 = await WebCrypto.genAESKey();
        await WebCrypto.decrypt(key2, ciphertext);
      } catch (error) {
        err = error;
      }
      assert.equal(err.message, 'Unable to decrypt data');
    });

    it('Should generate an extractable AES key cryptokey with default settings (AES-GCM 128 bits)', async () => {
      const key = await WebCrypto.genAESKey();
      assert.equal(key.type, 'secret', 'Secret key');
      assert.isTrue(key.extractable);
    });

    it('Should generate and export (in raw format by default) an extractable AES key cryptokey with default settings (AES-GCM 128 bits)', async () => {
      const key = await WebCrypto.genAESKey();
      const rawKey = await WebCrypto.exportKey(key);
      assert.lengthOf(rawKey, 16);
    });

    it('Should generate and export (in raw format by default) an extractable AES key cryptokey with default settings (AES-GCM 256 bits)', async () => {
      const key = await WebCrypto.genAESKey(true, 'AES-GCM', 256);
      const rawKey = await WebCrypto.exportKey(key);
      assert.lengthOf(rawKey, 32);
    });

    it('Should generate and export in raw format an extractable AES key cryptokey with default settings (AES-GCM 128 bits)', async () => {
      const key = await WebCrypto.genAESKey();
      const rawKey = await WebCrypto.exportKey(key, 'raw');
      assert.lengthOf(rawKey, 16);
    });

    it('Should encrypt a message and encode with default format (hex)', async () => {
      const message = { data: 'hello' };
      const key = await WebCrypto.genAESKey();
      const ciphertext = await WebCrypto.encrypt(key, message);
      assert.lengthOf(ciphertext.iv, 24);
    });

    it('Should encrypt a message and encode with base64 format ', async () => {
      const message = { data: 'hello' };
      const key = await WebCrypto.genAESKey();
      const ciphertext = await WebCrypto.encrypt(key, message, 'base64');

      assert.equal(ciphertext.ciphertext.slice(-1), '=');
    });

    it('Should encrypt and decrypt a message with default parameters', async () => {
      const message = { data: 'hello' };
      const key = await WebCrypto.genAESKey();
      const ciphertext = await WebCrypto.encrypt(key, message);
      const plaintext = await WebCrypto.decrypt(key, ciphertext);
      assert.deepEqual(plaintext, message);
    });

    it('Should generate/encrypt/export/import/decrypt with raw format for key export', async () => {
      const message = { data: 'hello' };
      const key = await WebCrypto.genAESKey();
      const ciphertext = await WebCrypto.encrypt(key, message);
      const rawKey = await WebCrypto.exportKey(key);
      const cryptoKey = await WebCrypto.importKey(rawKey);
      const plaintext = await WebCrypto.decrypt(cryptoKey, ciphertext);
      assert.deepEqual(plaintext, message);
    });

    it('Should generate/encrypt/export/import/decrypt with jwk format for key export', async () => {
      const message = { data: 'hello' };
      const key = await WebCrypto.genAESKey();
      const encrypted = await WebCrypto.encrypt(key, message);
      const jwk = await WebCrypto.exportKey(key, 'jwk');
      const cryptoKey = await WebCrypto.importKey(jwk, 'jwk');
      const plaintext = await WebCrypto.decrypt(cryptoKey, encrypted);
      assert.deepEqual(plaintext, message);
    });
  });

  describe('Passphrase key derivation', () => {
    const passphrase = 'mySecretPass';

    it('Should reject if passphrase is not a string or is empty', async () => {
      let err: any;
      try {
        await WebCrypto.genEncryptedMasterKey([] as any);
      } catch (error) {
        err = error;
      }
      assert.equal(err.message, 'Not a valid value');
    });

    it('Should reject if the any property of protectedMK is missing or empty', async () => {
      let err: any;
      try {
        await WebCrypto.decryptMasterKey('secretPassphraseCandidate', {} as any);
      } catch (error) {
        err = error;
      }
      assert.equal(err.message, 'Missing properties from master key');
    });

    it('Should reject if the given passphrase is NOT the same as the stored one', async () => {
      let err: any;
      try {
        const protectedMK = await WebCrypto.genEncryptedMasterKey(passphrase);
        await WebCrypto.decryptMasterKey(passphrase + 'modifed', protectedMK);
      } catch (error) {
        err = error;
      }

      assert.strictEqual(err.message, 'Wrong passphrase');
    });

    it('Should derive a passphrase with default settings, generate MK and encrypt it', async () => {
      const protectedMasterKey = await WebCrypto.genEncryptedMasterKey(passphrase);
      const { derivationParams, encryptedMasterKey } = protectedMasterKey;
      const { salt, iterations, hashAlgo } = derivationParams;
      assert.equal(hashAlgo, 'SHA-256', 'Default hash algo is SHA-256');
      assert.equal(iterations, 100000, 'Default iteration is 100000');
      assert.lengthOf(salt, 32, 'Default salt is 128 bits array, 32 bytes as hex string');
      assert.exists(encryptedMasterKey.iv);
      assert.exists(encryptedMasterKey.ciphertext);
    });

    it('Should update the passphrase but keep the same MK', async () => {
      const newPassphrase = 'newPassphrase';

      const protectedMasterKey1 = await WebCrypto.genEncryptedMasterKey(passphrase);
      const protectedMasterKey2 = await WebCrypto.updatePassphraseKey(passphrase, newPassphrase, protectedMasterKey1);

      assert.notEqual(protectedMasterKey1.encryptedMasterKey, protectedMasterKey2.encryptedMasterKey);

      assert.notEqual(protectedMasterKey1.encryptedMasterKey.ciphertext,
        protectedMasterKey2.encryptedMasterKey.ciphertext);

      assert.equal(protectedMasterKey1.derivationParams.hashAlgo,
        protectedMasterKey1.derivationParams.hashAlgo,
        'Default hash algo is SHA-256');

      assert.equal(protectedMasterKey1.derivationParams.iterations,
        protectedMasterKey2.derivationParams.iterations,
        'Default iteration is 100000');

      // Check if the masterkey is the same
      const decMK1 = await WebCrypto.decryptMasterKey(passphrase, protectedMasterKey1);
      const decMK2 = await WebCrypto.decryptMasterKey(newPassphrase, protectedMasterKey2);
      const key1 = Buffer.from(await WebCrypto.exportKey(decMK1) as Uint8Array).toString('hex');
      const key2 = Buffer.from(await WebCrypto.exportKey(decMK2) as Uint8Array).toString('hex');
      assert.equal(key1, key2);
    });

    it('Should return the MK (an Array) if the given passphrase is the same as the stored one', async () => {
      const protectedMK = await WebCrypto.genEncryptedMasterKey(passphrase);
      const masterKey = await WebCrypto.decryptMasterKey(passphrase, protectedMK);

      assert.exists(masterKey, 'The check operation should return the MK');
      assert.lengthOf(await WebCrypto.exportKey(masterKey), 32);
    });

    it('Should derive a key from passphrase, gen MK, enc/dec a value', async () => {
      const protectedMK = await WebCrypto.genEncryptedMasterKey(passphrase);
      const cryptokey = await WebCrypto.decryptMasterKey(passphrase, protectedMK);
      const data = { hello: 'world' };
      const enc = await WebCrypto.encrypt(cryptokey, data);
      assert.exists(enc.iv, 'iv must exist');
      assert.exists(enc.ciphertext, 'ciphertext must exist');

      // Just to be sure that everything is working well.
      const dec = await WebCrypto.decrypt(cryptokey, enc);
      assert.deepEqual(dec, data);
    });

    it('The salt and protectedMK must be different for two consecutive call to genEncryptedMasterKey even with the same passphrase', async () => {
      const passphrase = 'secret';
      const protectedMK1 = await WebCrypto.genEncryptedMasterKey(passphrase);
      const protectedMK2 = await WebCrypto.genEncryptedMasterKey(passphrase);
      assert.notStrictEqual(protectedMK1.derivationParams.salt, protectedMK2.derivationParams.salt);
      assert.notStrictEqual(protectedMK1.encryptedMasterKey.iv, protectedMK2.encryptedMasterKey.iv);
      assert.notStrictEqual(protectedMK1.encryptedMasterKey.ciphertext, protectedMK2.encryptedMasterKey.ciphertext);
    });
  });

  describe('Decryption failures', () => {
    const getKey = () => WebCrypto.genAESKey();

    it('Should map the browser authentication failure to a stable message', async () => {
      const key = await getKey();
      const spy = vi.spyOn(globalThis.crypto.subtle, 'decrypt').mockRejectedValue(
        new Error('Unsupported state or unable to authenticate data')
      );
      try {
        await expect(
          WebCrypto.decryptBuffer(key, new Uint8Array([1, 2, 3]), { name: 'AES-GCM' })
        ).rejects.toThrow('Unable to decrypt data');
      } finally {
        spy.mockRestore();
      }
    });

    it('Should wrap a thrown string in an Error', async () => {
      const key = await getKey();
      const spy = vi.spyOn(globalThis.crypto.subtle, 'decrypt').mockImplementation(() => {
        return Promise.reject('some legacy failure');
      });
      try {
        await expect(
          WebCrypto.decryptBuffer(key, new Uint8Array([1, 2, 3]), { name: 'AES-GCM' })
        ).rejects.toThrow('some legacy failure');
      } finally {
        spy.mockRestore();
      }
    });

    it('Should resolve undefined when the failure is of an unrecognised shape', async () => {
      // Documents current behaviour: decryptBuffer swallows anything that is
      // neither the known message nor a string. decrypt() turns that undefined
      // into a proper error, so no caller of decrypt() ever sees it.
      const key = await getKey();
      const spy = vi.spyOn(globalThis.crypto.subtle, 'decrypt').mockRejectedValue({ code: 42 });
      try {
        const out = await WebCrypto.decryptBuffer(key, new Uint8Array([1, 2, 3]), { name: 'AES-GCM' });
        assert.isUndefined(out);
      } finally {
        spy.mockRestore();
      }
    });

    it('Should refuse to decrypt with the wrong key', async () => {
      const good = await getKey();
      const wrong = await getKey();
      const enc = await WebCrypto.encrypt(good, { hello: 'world' });

      let err: any;
      try {
        await WebCrypto.decrypt(wrong, enc);
      } catch (error) {
        err = error;
      }
      assert.equal(err.message, 'Unable to decrypt data');
    });

    it('Should refuse to decrypt a tampered ciphertext', async () => {
      const key = await getKey();
      const enc = await WebCrypto.encrypt(key, { hello: 'world' });
      // flip the last byte of the ciphertext, which invalidates the GCM tag
      const bytes = Buffer.from(enc.ciphertext, 'hex');
      bytes[bytes.length - 1] ^= 0xff;
      const tampered = { ...enc, ciphertext: bytes.toString('hex') };

      let err: any;
      try {
        await WebCrypto.decrypt(key, tampered);
      } catch (error) {
        err = error;
      }
      assert.equal(err.message, 'Unable to decrypt data');
    });

    it('Should refuse to decrypt with the wrong iv', async () => {
      const key = await getKey();
      const enc = await WebCrypto.encrypt(key, { hello: 'world' });
      const wrongIv = { ...enc, iv: WebCrypto._genRandomBufferAsStr(16, 'hex') };

      let err: any;
      try {
        await WebCrypto.decrypt(key, wrongIv);
      } catch (error) {
        err = error;
      }
      assert.equal(err.message, 'Unable to decrypt data');
    });
  });
});
