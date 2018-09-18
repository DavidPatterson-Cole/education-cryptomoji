'use strict';

const { createHash } = require('crypto');
const signing = require('./signing');

/**
 * A simple validation function for transactions. Accepts a transaction
 * and returns true or false. It should reject transactions that:
 *   - have negative amounts
 *   - were improperly signed
 *   - have been modified since signing
 */
const isValidTransaction = transaction => {
  // Enter your solution here
  // let verify = signing.verify(transaction.source, transaction.amount, )
  if (transaction.amount < 0) {
    return false;
  }
  if (!signing.verify(transaction.source, transaction.source + transaction.recipient + transaction.amount, transaction.signature)) {
    return false;
  }
  return true;
};

/**
 * Validation function for blocks. Accepts a block and returns true or false.
 * It should reject blocks if:
 *   - their hash or any other properties were altered
 *   - they contain any invalid transactions
 */
const isValidBlock = block => {
  // Your code here
  for (let transaction of block.transactions) {
    if (!isValidTransaction(transaction)) {
      return false;
    }
  }
  // Not sure why I can't access block.calculateHash - so have to use not DRY approach with createHash
  // console.log(`hash: ${block.hash}`);
  // console.log(`check: ${createHash('sha256').update(JSON.stringify(block.transactions) + block.previousHash + block.nonce).digest('hex')}`);
  if (block.hash !== createHash('sha256').update(JSON.stringify(block.transactions) + block.previousHash + block.nonce).digest('hex')) {
    return false;
  }
  return true;
};

/**
 * One more validation function. Accepts a blockchain, and returns true
 * or false. It should reject any blockchain that:
 *   - is a missing genesis block
 *   - has any block besides genesis with a null hash
 *   - has any block besides genesis with a previousHash that does not match
 *     the previous hash
 *   - contains any invalid blocks
 *   - contains any invalid transactions
 */
const isValidChain = blockchain => {
  // Your code here
  if (blockchain.blocks[0].previousHash !== null) {
    return false;
  }
  for (let i = 1; i < blockchain.blocks.length; i++) {
    if (blockchain.blocks[i].previousHash !== blockchain.blocks[i - 1].hash) {
      return false;
    }
  }
  for (let block of blockchain.blocks) {
    if (!isValidBlock(block)) {
      return false;
    }
    for (let transaction of block.transactions) {
      if (!isValidTransaction(transaction)) {
        return false;
      }
    }
  }
  return true;
};

/**
 * This last one is just for fun. Become a hacker and tamper with the passed in
 * blockchain, mutating it for your own nefarious purposes. This should
 * (in theory) make the blockchain fail later validation checks;
 */
const breakChain = blockchain => {
  // Your code here
  blockchain.blocks[blockchain.blocks.length - 1].transactions[0].amount = 10000;
};

module.exports = {
  isValidTransaction,
  isValidBlock,
  isValidChain,
  breakChain
};
