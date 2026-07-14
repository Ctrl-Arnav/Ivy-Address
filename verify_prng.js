// Cross-language PRNG verification — run with: node verify_prng.js
// Expected output must match Python's prng.py self_test output.

class Xoshiro128StarStar {
  constructor(s0, s1, s2, s3) {
    this.s = new Uint32Array([s0, s1, s2, s3]);
  }
  static rotl(x, k) {
    return ((x << k) | (x >>> (32 - k))) >>> 0;
  }
  next() {
    const s = this.s;
    const result = (Math.imul(Xoshiro128StarStar.rotl(Math.imul(s[1], 5), 7), 9)) >>> 0;
    const t = (s[1] << 9) >>> 0;
    s[2] = (s[2] ^ s[0]) >>> 0;
    s[3] = (s[3] ^ s[1]) >>> 0;
    s[1] = (s[1] ^ s[2]) >>> 0;
    s[0] = (s[0] ^ s[3]) >>> 0;
    s[2] = (s[2] ^ t) >>> 0;
    s[3] = Xoshiro128StarStar.rotl(s[3], 11);
    return result;
  }
}

// Same seed as Python self_test: (1, 2, 3, 4)
const prng = new Xoshiro128StarStar(1, 2, 3, 4);
const first10 = [];
for (let i = 0; i < 10; i++) {
  first10.push(prng.next());
}

console.log("JS Xoshiro128** first 10 from seed (1,2,3,4):");
console.log(first10);

// Python produced: [11520, 0, 5927040]
const pyFirst3 = [11520, 0, 5927040];
const match = first10[0] === pyFirst3[0] && first10[1] === pyFirst3[1] && first10[2] === pyFirst3[2];
console.log(`Cross-language match (first 3): ${match ? "✓ PASS" : "✗ FAIL"}`);

if (!match) {
  console.log(`  Expected: ${pyFirst3}`);
  console.log(`  Got:      ${first10.slice(0, 3)}`);
}
