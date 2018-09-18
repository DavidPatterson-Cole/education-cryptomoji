'use strict';

const secp256k1 = require('secp256k1');
const { randomBytes, createHash } = require('crypto');


/**
 * A function which generates a new random Secp256k1 private key, returning
 * it as a 64 character hexadecimal string.
 *
 * Example:
 *   const privateKey = createPrivateKey();
 *   console.log(privateKey);
 *   // 'e291df3eede7f0c520fddbe5e9e53434ff7ef3c0894ed9d9cbcb6596f1cfe87e'
 */
const createPrivateKey = () => {
  // Enter your solution here
  let privKey;
  do {
    privKey = randomBytes(32);
  } while (!secp256k1.privateKeyVerify(privKey));
  // crypto.randomBytes(64, (err, buf) => {
  //   if (err) throw err;
  //   console.log(`${buf.length} bytes of random data: ${buf.toString('hex')}`);
  // });
  return privKey.toString('hex');
};

/**
 * A function which takes a hexadecimal private key and returns its public pair
 * as a 66 character hexadecimal string.
 *
 * Example:
 *   const publicKey = getPublicKey(privateKey);
 *   console.log(publicKey);
 *   // '0202694593ddc71061e622222ed400f5373cfa7ea607ce106cca3f039b0f9a0123'
 *
 * Hint:
 *   Remember that the secp256k1-node library expects raw bytes (i.e Buffers),
 *   not hex strings! You'll have to convert the private key.
 */
const getPublicKey = privateKey => {
  // Your code here
  // console.log(`public key: ${secp256k1.publicKeyCreate(Buffer.from(privateKey, 'hex')).toString('hex')}`);
  // console.log(`private key: ${privateKey}`);
  return secp256k1.publicKeyCreate(Buffer.from(privateKey, 'hex')).toString('hex');
};

/**
 * A function which takes a hex private key and a string message, returning
 * a 128 character hexadecimal signature.
 *
 * Example:
 *   const signature = sign(privateKey, 'Hello World!');
 *   console.log(signature);
 *   // '4ae1f0b20382ad628804a5a66e09cc6bdf2c83fa64f8017e98d84cc75a1a71b52...'
 *
 * Hint:
 *   Remember that you need to sign a SHA-256 hash of the message,
 *   not the message itself!
 */
const sign = (privateKey, message) => {
  // Your code here
  const hash = createHash('sha256');
  hash.update(message);
  // console.log(`hash: ${hash}`);
  // console.log(`hash: ${Buffer.from(hash.digest('hex'), 'hex')}`);
  // console.log(`private key: ${Buffer.from(privateKey, 'hex')}`);
  // console.log(`hash digest: ${hash.digest('hex')}`);
  return secp256k1.sign(Buffer.from(hash.digest('hex'), 'hex'), Buffer.from(privateKey, 'hex')).signature.toString('hex');
};

/**
 * A function which takes a hex public key, a string message, and a hex
 * signature, and returns either true or false.
 *
 * Example:
 *   console.log( verify(publicKey, 'Hello World!', signature) );
 *   // true
 *   console.log( verify(publicKey, 'Hello World?', signature) );
 *   // false
 */
const verify = (publicKey, message, signature) => {
  // apparently necessary to rehash
  const hash = createHash('sha256');
  hash.update(message);

  // console.log(Buffer.isBuffer(Buffer.from(message, 'utf8')));
  // console.log(`message: ${Buffer.from(message, 'utf8')}`);
  // console.log(`signature: ${Buffer.from(signature, 'hex')}`);
  // console.log(`public key: ${Buffer.from(publicKey, 'hex')}`);
  return secp256k1.verify(Buffer.from(hash.digest('hex'), 'hex'), Buffer.from(signature, 'hex'), Buffer.from(publicKey, 'hex'));
};

module.exports = {
  createPrivateKey,
  getPublicKey,
  sign,
  verify
};
