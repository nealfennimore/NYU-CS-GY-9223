const { parentPort, workerData } = require("worker_threads");
const a = require("./a.js");

function isEqualBuffer(a, b) {
  const dvA = new DataView(a);
  const dvB = new DataView(b);

  if (dvA.byteLength !== dvB.byteLength) {
    return false;
  }

  for (let i = 0; i < dvA.byteLength; i++) {
    if (dvA.getUint8(i) !== dvB.getUint8(i)) {
      return false;
    }
  }

  return true;
}

function* genKey(start, end) {
  function numberToArrayBuffer(value) {
    const view = new DataView(new ArrayBuffer(16));
    for (var index = 15; index >= 0; --index) {
      view.setUint8(index, value % 256);
      value = value >> 8;
    }
    return Array.from(new Uint8Array(view.buffer));
  }
  while (start <= end) {
    yield numberToArrayBuffer(++start);
  }
}

function tryDecrypt(key, { ciphertextBytes, contentBytes, iv }) {
  const decryptionKey = new a.M.cb(key, iv);
  const plaintext = decryptionKey.d(ciphertextBytes);

  return isEqualBuffer(contentBytes.buffer, plaintext.buffer);
}

function main({ start, end, ...rest }) {
  const keygen = genKey(start, end);

  while (true) {
    const next = keygen.next();
    if (next.done) {
      return null;
    }
    const key = next.value;
    if (tryDecrypt(key, rest)) {
      return key;
    }
  }
}

module.exports = main;
