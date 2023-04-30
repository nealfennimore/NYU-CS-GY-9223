const Piscina = require("piscina");
const path = require("path");
const { Worker } = require("worker_threads");
const a = require("./a.js");

const content = `Hey Alice,

Long time no hack!!!! It feels like ages since we last caught up. Hope you're doing well and staying out of trouble. As usual, the digital world has been keeping me on my toes, but I've been missing our hacker-in-crime duo!

We definitely need to catch up on some important matters. There's been some interesting developments that I'm dying to discuss with you. Remember that project we were working on last month? I've made some major breakthroughs since then and I can't wait to share the details with you.

But here's the catch - I seem to have misplaced my encryption key. Yep, classic me! I've turned my entire virtual world upside down trying to find it, but no luck so far. You know me, always trying to encrypt my messages to keep things top secret.

Once you've received this email it means I've found it. I know it's around here somewhere.......
            `;

const contentBytes = a.utils.utf8.toBytes(content);
const initialKey = [
  1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
  23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
];
const iv = [21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36];
const encryptionKey = new a.M.cb(initialKey, iv);
const ciphertextBytes = encryptionKey.e(contentBytes); // Uint8Array

const piscina = new Piscina({
  filename: path.resolve(__dirname, "worker.js"),
  maxQueue: "auto",
});

const INCREMENT = 10000;

(async function () {
  let current = 0;

  while (true) {
    const tasks = Promise.all(
      new Array(32).fill(null).map(() => {
        const start = current;
        const end = current + INCREMENT;
        current = end + 1;
        return piscina.run({ start, end, ciphertextBytes, contentBytes, iv });
      })
    );

    console.log(current, piscina.utilization, piscina.waitTime.average);

    const responses = await tasks;

    if (responses.some((response) => response !== null)) {
      const result = responses.find((response) => response !== null);
      console.log(`Found key: ${result}`);
      break;
    }
  }
})();
