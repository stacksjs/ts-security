// Basic JavaScript BN library - subset useful for RSA encryption.

/*
Licensing (LICENSE)
-------------------

This software is covered under the following copyright:
*/
/*
 * Copyright (c) 2003-2005  Tom Wu
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS-IS" AND WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS, IMPLIED OR OTHERWISE, INCLUDING WITHOUT LIMITATION, ANY
 * WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
 *
 * IN NO EVENT SHALL TOM WU BE LIABLE FOR ANY SPECIAL, INCIDENTAL,
 * INDIRECT OR CONSEQUENTIAL DAMAGES OF ANY KIND, OR ANY DAMAGES WHATSOEVER
 * RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER OR NOT ADVISED OF
 * THE POSSIBILITY OF DAMAGE, AND ON ANY THEORY OF LIABILITY, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * In addition, the following condition applies:
 *
 * All redistributions must retain an intact copy of this copyright notice
 * and disclaimer.
 */
/*
Address all questions regarding this license to:

  Tom Wu
  tjw@cs.Stanford.EDU
*/

// Types for the reduction algorithms
interface IReducer {
  convert(x: BigInteger): BigInteger;
  revert(x: BigInteger): BigInteger;
  reduce(x: BigInteger): void;
  mulTo(x: BigInteger, y: BigInteger, r: BigInteger): void;
  sqrTo(x: BigInteger, r: BigInteger): void;
}

// PRNG interface
interface IPRNG {
  nextBytes(x: number[]): void;
}

export class BigInteger {
  private static readonly DB = (() => {
    const canary = 0xdeadbeefcafe;
    const j_lm = ((canary & 0xffffff) == 0xefcafe);

    if (typeof navigator === 'undefined') return 28;  // node.js
    if (j_lm && navigator.appName === "Microsoft Internet Explorer") return 30;
    if (j_lm && navigator.appName !== "Netscape") return 26;
    return 28;  // Mozilla/Netscape
  })();

  private static readonly DM = ((1 << BigInteger.DB) - 1);
  private static readonly DV = (1 << BigInteger.DB);
  private static readonly FP = 52;
  private static readonly FV = Math.pow(2, BigInteger.FP);
  private static readonly F1 = BigInteger.FP - BigInteger.DB;
  private static readonly F2 = 2 * BigInteger.DB - BigInteger.FP;

  static readonly ZERO = new BigInteger(0);
  static readonly ONE = new BigInteger(1);

  private data: number[] = [];
  private t: number = 0;  // Array length
  private s: number = 0;  // Sign

  constructor(value?: number | string | null, radix?: number, length?: number) {
    if (value != null) {
      if (typeof value === "number") {
        this.fromNumber(value, length || 0, radix || 0);
      } else if (radix == null && typeof value !== "string") {
        this.fromString(value, 256);
      } else {
        this.fromString(value, radix || 10);
      }
    }
  }

  private static readonly BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz";
  private static readonly BI_RC: number[] = (() => {
    const rc: number[] = new Array(256);
    let rr = "0".charCodeAt(0);
    for (let vv = 0; vv <= 9; ++vv) rc[rr++] = vv;
    rr = "a".charCodeAt(0);
    for (let vv = 10; vv < 36; ++vv) rc[rr++] = vv;
    rr = "A".charCodeAt(0);
    for (let vv = 10; vv < 36; ++vv) rc[rr++] = vv;
    return rc;
  })();

  // am: Compute w_j += (x*this_i), propagate carries
  private am(i: number, x: number, w: BigInteger, j: number, c: number, n: number): number {
    const xl = x & 0x3fff;
    const xh = x >> 14;
    while (--n >= 0) {
      let l = this.data[i] & 0x3fff;
      let h = this.data[i++] >> 14;
      let m = xh * l + h * xl;
      l = xl * l + ((m & 0x3fff) << 14) + w.data[j] + c;
      c = (l >> 28) + (m >> 14) + xh * h;
      w.data[j++] = l & 0xfffffff;
    }
    return c;
  }

  private fromNumber(value: number, length: number, randomizer?: IPRNG | number): void {
    if (typeof randomizer === "number") {
      // New BigInteger(int, int, RNG)
      if (value < 2) {
        this.fromInt(1);
      } else {
        this.fromNumber(value, randomizer);
        if (!this.testBit(value - 1)) {
          this.bitwiseTo(BigInteger.ONE.shiftLeft(value - 1), this.op_or, this);
        }
        if (this.isEven()) {
          this.dAddOffset(1, 0);
        }
        while (!this.isProbablePrime(randomizer)) {
          this.dAddOffset(2, 0);
          if (this.bitLength() > value) {
            this.subTo(BigInteger.ONE.shiftLeft(value - 1), this);
          }
        }
      }
    } else if (randomizer) {
      // New BigInteger(int, RNG)
      const x = new Array();
      const t = value & 7;
      x.length = (value >> 3) + 1;
      randomizer.nextBytes(x);
      if (t > 0) {
        x[0] &= ((1 << t) - 1);
      } else {
        x[0] = 0;
      }
      this.fromString(x, 256);
    }
  }

  private fromInt(value: number): void {
    this.t = 1;
    this.s = (value < 0) ? -1 : 0;
    if (value > 0) {
      this.data[0] = value;
    } else if (value < -1) {
      this.data[0] = value + BigInteger.DV;
    } else {
      this.t = 0;
    }
  }

  private fromString(s: string | number[], b: number): void {
    let k: number;
    if (b === 16) k = 4;
    else if (b === 8) k = 3;
    else if (b === 256) k = 8;
    else if (b === 2) k = 1;
    else if (b === 32) k = 5;
    else if (b === 4) k = 2;
    else {
      this.fromRadix(s as string, b);
      return;
    }

    this.t = 0;
    this.s = 0;
    let i = s.length;
    let mi = false;
    let sh = 0;

    while (--i >= 0) {
      const x = (k === 8) ? (s[i] as number) & 0xff : this.intAt(s as string, i);
      if (x < 0) {
        if ((s as string).charAt(i) === "-") mi = true;
        continue;
      }
      mi = false;
      if (sh === 0) {
        this.data[this.t++] = x;
      } else if (sh + k > BigInteger.DB) {
        this.data[this.t - 1] |= (x & ((1 << (BigInteger.DB - sh)) - 1)) << sh;
        this.data[this.t++] = (x >> (BigInteger.DB - sh));
      } else {
        this.data[this.t - 1] |= x << sh;
      }
      sh += k;
      if (sh >= BigInteger.DB) sh -= BigInteger.DB;
    }

    if (k === 8 && ((s[0] as number) & 0x80) !== 0) {
      this.s = -1;
      if (sh > 0) {
        this.data[this.t - 1] |= ((1 << (BigInteger.DB - sh)) - 1) << sh;
      }
    }

    this.clamp();
    if (mi) BigInteger.ZERO.subTo(this, this);
  }

  // Utility methods
  private static int2char(n: number): string {
    return BigInteger.BI_RM.charAt(n);
  }

  private intAt(s: string, i: number): number {
    const c = BigInteger.BI_RC[s.charCodeAt(i)];
    return (c == null) ? -1 : c;
  }

  private clamp(): void {
    const c = this.s & BigInteger.DM;
    while (this.t > 0 && this.data[this.t - 1] === c) --this.t;
  }

  // Public methods from the original implementation
  public toString(b: number = 10): string {
    if (this.s < 0) return "-" + this.negate().toString(b);
    let k: number;
    if (b === 16) k = 4;
    else if (b === 8) k = 3;
    else if (b === 2) k = 1;
    else if (b === 32) k = 5;
    else if (b === 4) k = 2;
    else return this.toRadix(b);

    const km = (1 << k) - 1;
    let d: number;
    let m = false;
    let r = "";
    let i = this.t;
    let p = BigInteger.DB - (i * BigInteger.DB) % k;

    if (i-- > 0) {
      if (p < BigInteger.DB && (d = this.data[i] >> p) > 0) {
        m = true;
        r = BigInteger.int2char(d);
      }
      while (i >= 0) {
        if (p < k) {
          d = (this.data[i] & ((1 << p) - 1)) << (k - p);
          d |= this.data[--i] >> (p += BigInteger.DB - k);
        } else {
          d = (this.data[i] >> (p -= k)) & km;
          if (p <= 0) {
            p += BigInteger.DB;
            --i;
          }
        }
        if (d > 0) m = true;
        if (m) r += BigInteger.int2char(d);
      }
    }
    return m ? r : "0";
  }

  public negate(): BigInteger {
    const r = new BigInteger();
    BigInteger.ZERO.subTo(this, r);
    return r;
  }

  public abs(): BigInteger {
    return (this.s < 0) ? this.negate() : this;
  }

  public compareTo(a: BigInteger): number {
    let r = this.s - a.s;
    if (r !== 0) return r;
    let i = this.t;
    r = i - a.t;
    if (r !== 0) return (this.s < 0) ? -r : r;
    while (--i >= 0) {
      if ((r = this.data[i] - a.data[i]) !== 0) return r;
    }
    return 0;
  }

  public bitLength(): number {
    if (this.t <= 0) return 0;
    return BigInteger.DB * (this.t - 1) +
      this.nbits(this.data[this.t - 1] ^ (this.s & BigInteger.DM));
  }

  private nbits(x: number): number {
    let r = 1;
    let t: number;
    if ((t = x >>> 16) !== 0) { x = t; r += 16; }
    if ((t = x >> 8) !== 0) { x = t; r += 8; }
    if ((t = x >> 4) !== 0) { x = t; r += 4; }
    if ((t = x >> 2) !== 0) { x = t; r += 2; }
    if ((t = x >> 1) !== 0) { x = t; r += 1; }
    return r;
  }

  // Add more public methods as needed...

  // Helper methods
  private op_or(x: number, y: number): number { return x | y; }
  private op_and(x: number, y: number): number { return x & y; }
  private op_xor(x: number, y: number): number { return x ^ y; }
  private op_andnot(x: number, y: number): number { return x & ~y; }

  private bitwiseTo(a: BigInteger, op: (x: number, y: number) => number, r: BigInteger): void {
    let i: number;
    const f = Math.min(a.t, this.t);
    for (i = 0; i < f; ++i) r.data[i] = op(this.data[i], a.data[i]);
    if (a.t < this.t) {
      const f = a.s & BigInteger.DM;
      for (i = f; i < this.t; ++i) r.data[i] = op(this.data[i], f);
      r.t = this.t;
    } else {
      const f = this.s & BigInteger.DM;
      for (i = f; i < a.t; ++i) r.data[i] = op(f, a.data[i]);
      r.t = a.t;
    }
    r.s = op(this.s, a.s);
    r.clamp();
  }

  // Additional arithmetic operations...
  public add(a: BigInteger): BigInteger {
    const r = new BigInteger();
    this.addTo(a, r);
    return r;
  }

  private addTo(a: BigInteger, r: BigInteger): void {
    let i = 0;
    let c = 0;
    const m = Math.min(a.t, this.t);
    while (i < m) {
      c += this.data[i] + a.data[i];
      r.data[i++] = c & BigInteger.DM;
      c >>= BigInteger.DB;
    }
    if (a.t < this.t) {
      c += a.s;
      while (i < this.t) {
        c += this.data[i];
        r.data[i++] = c & BigInteger.DM;
        c >>= BigInteger.DB;
      }
      c += this.s;
    } else {
      c += this.s;
      while (i < a.t) {
        c += a.data[i];
        r.data[i++] = c & BigInteger.DM;
        c >>= BigInteger.DB;
      }
      c += a.s;
    }
    r.s = (c < 0) ? -1 : 0;
    if (c > 0) r.data[i++] = c;
    else if (c < -1) r.data[i++] = BigInteger.DV + c;
    r.t = i;
    r.clamp();
  }

  // Method to check if number is probably prime
  public isProbablePrime(t: number): boolean {
    const x = this.abs();
    if (x.t === 1 && x.data[0] <= lowprimes[lowprimes.length - 1]) {
      for (let i = 0; i < lowprimes.length; ++i) {
        if (x.data[0] === lowprimes[i]) return true;
      }
      return false;
    }
    if (x.isEven()) return false;

    let i = 1;
    while (i < lowprimes.length) {
      let m = lowprimes[i];
      let j = i + 1;
      while (j < lowprimes.length && m < lplim) m *= lowprimes[j++];
      m = x.modInt(m);
      while (i < j) if (m % lowprimes[i++] === 0) return false;
    }
    return x.millerRabin(t);
  }

  // Miller-Rabin primality test
  private millerRabin(t: number): boolean {
    const n1 = this.subtract(BigInteger.ONE);
    const k = n1.getLowestSetBit();
    if (k <= 0) return false;
    const r = n1.shiftRight(k);

    for (let i = 0; i < t; ++i) {
      // Select witness 'a' at random between 1 and n1
      let a: BigInteger;
      do {
        a = new BigInteger(this.bitLength(), this.getPrng());
      } while (a.compareTo(BigInteger.ONE) <= 0 || a.compareTo(n1) >= 0);

      let y = a.modPow(r, this);
      if (y.compareTo(BigInteger.ONE) !== 0 && y.compareTo(n1) !== 0) {
        let j = 1;
        while (j++ < k && y.compareTo(n1) !== 0) {
          y = y.modPowInt(2, this);
          if (y.compareTo(BigInteger.ONE) === 0) return false;
        }
        if (y.compareTo(n1) !== 0) return false;
      }
    }
    return true;
  }

  private getPrng(): IPRNG {
    return {
      nextBytes(x: number[]): void {
        for (let i = 0; i < x.length; ++i) {
          x[i] = Math.floor(Math.random() * 0x0100);
        }
      }
    };
  }

  // Additional arithmetic operations
  public subtract(a: BigInteger): BigInteger {
    const r = new BigInteger();
    this.subTo(a, r);
    return r;
  }

  private subTo(a: BigInteger, r: BigInteger): void {
    let i = 0;
    let c = 0;
    const m = Math.min(a.t, this.t);
    while (i < m) {
      c += this.data[i] - a.data[i];
      r.data[i++] = c & BigInteger.DM;
      c >>= BigInteger.DB;
    }
    if (a.t < this.t) {
      c -= a.s;
      while (i < this.t) {
        c += this.data[i];
        r.data[i++] = c & BigInteger.DM;
        c >>= BigInteger.DB;
      }
      c += this.s;
    } else {
      c += this.s;
      while (i < a.t) {
        c -= a.data[i];
        r.data[i++] = c & BigInteger.DM;
        c >>= BigInteger.DB;
      }
      c -= a.s;
    }
    r.s = (c < 0) ? -1 : 0;
    if (c < -1) r.data[i++] = BigInteger.DV + c;
    else if (c > 0) r.data[i++] = c;
    r.t = i;
    r.clamp();
  }

  // Modular arithmetic
  public modPow(e: BigInteger, m: BigInteger): BigInteger {
    let i = e.bitLength();
    let k: number;
    let r = new BigInteger(1);
    let z: IReducer;

    if (i <= 0) return r;
    else if (i < 18) k = 1;
    else if (i < 48) k = 3;
    else if (i < 144) k = 4;
    else if (i < 768) k = 5;
    else k = 6;

    if (i < 8) {
      z = new Classic(m);
    } else if (m.isEven()) {
      z = new Barrett(m);
    } else {
      z = new Montgomery(m);
    }

    // Precomputation
    const g: BigInteger[] = [];
    let n = 3;
    const k1 = k - 1;
    const km = (1 << k) - 1;
    g[1] = z.convert(this);

    if (k > 1) {
      const g2 = new BigInteger();
      z.sqrTo(g[1], g2);
      while (n <= km) {
        g[n] = new BigInteger();
        z.mulTo(g2, g[n - 2], g[n]);
        n += 2;
      }
    }

    let j = e.t - 1;
    let w: number;
    let is1 = true;
    let r2 = new BigInteger();
    let t: BigInteger;
    i = this.nbits(e.data[j]) - 1;

    while (j >= 0) {
      if (i >= k1) {
        w = (e.data[j] >> (i - k1)) & km;
      } else {
        w = (e.data[j] & ((1 << (i + 1)) - 1)) << (k1 - i);
        if (j > 0) {
          w |= e.data[j - 1] >> (BigInteger.DB + i - k1);
        }
      }

      n = k;
      while ((w & 1) === 0) {
        w >>= 1;
        --n;
      }
      if ((i -= n) < 0) {
        i += BigInteger.DB;
        --j;
      }

      if (is1) {
        g[w].copyTo(r);
        is1 = false;
      } else {
        while (n > 1) {
          z.sqrTo(r, r2);
          z.sqrTo(r2, r);
          n -= 2;
        }
        if (n > 0) {
          z.sqrTo(r, r2);
        } else {
          t = r;
          r = r2;
          r2 = t;
        }
        z.mulTo(r2, g[w], r);
      }

      while (j >= 0 && (e.data[j] & (1 << i)) === 0) {
        z.sqrTo(r, r2);
        t = r;
        r = r2;
        r2 = t;
        if (--i < 0) {
          i = BigInteger.DB - 1;
          --j;
        }
      }
    }
    return z.revert(r);
  }

  public modPowInt(e: number, m: BigInteger): BigInteger {
    let z: IReducer;
    if (e < 256 || m.isEven()) {
      z = new Classic(m);
    } else {
      z = new Montgomery(m);
    }
    return this.exp(e, z);
  }

  private exp(e: number, z: IReducer): BigInteger {
    if (e > 0xffffffff || e < 1) return BigInteger.ONE;
    let r = new BigInteger();
    let r2 = new BigInteger();
    const g = z.convert(this);
    let i = this.nbits(e) - 1;

    g.copyTo(r);
    while (--i >= 0) {
      z.sqrTo(r, r2);
      if ((e & (1 << i)) > 0) {
        z.mulTo(r2, g, r);
      } else {
        const t = r;
        r = r2;
        r2 = t;
      }
    }
    return z.revert(r);
  }

  // Utility methods
  public isEven(): boolean {
    return ((this.t > 0) ? (this.data[0] & 1) : this.s) === 0;
  }

  public modInt(n: number): number {
    if (n <= 0) return 0;
    const d = BigInteger.DV % n;
    let r = (this.s < 0) ? n - 1 : 0;
    if (this.t > 0) {
      if (d === 0) {
        r = this.data[0] % n;
      } else {
        for (let i = this.t - 1; i >= 0; --i) {
          r = (d * r + this.data[i]) % n;
        }
      }
    }
    return r;
  }

  public getLowestSetBit(): number {
    for (let i = 0; i < this.t; ++i) {
      if (this.data[i] !== 0) {
        return i * BigInteger.DB + this.lbit(this.data[i]);
      }
    }
    if (this.s < 0) return this.t * BigInteger.DB;
    return -1;
  }

  private lbit(x: number): number {
    if (x === 0) return -1;
    let r = 0;
    if ((x & 0xffff) === 0) { x >>= 16; r += 16; }
    if ((x & 0xff) === 0) { x >>= 8; r += 8; }
    if ((x & 0xf) === 0) { x >>= 4; r += 4; }
    if ((x & 3) === 0) { x >>= 2; r += 2; }
    if ((x & 1) === 0) ++r;
    return r;
  }
}

// Constants
const lowprimes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509];
const lplim = (1 << 26) / lowprimes[lowprimes.length - 1];

// Reducer implementations
class Classic implements IReducer {
  constructor(private m: BigInteger) { }

  convert(x: BigInteger): BigInteger {
    if (x.s < 0 || x.compareTo(this.m) >= 0) {
      return x.mod(this.m);
    }
    return x;
  }

  revert(x: BigInteger): BigInteger {
    return x;
  }

  reduce(x: BigInteger): void {
    x.divRemTo(this.m, null, x);
  }

  mulTo(x: BigInteger, y: BigInteger, r: BigInteger): void {
    x.multiplyTo(y, r);
    this.reduce(r);
  }

  sqrTo(x: BigInteger, r: BigInteger): void {
    x.squareTo(r);
    this.reduce(r);
  }
}

class Montgomery implements IReducer {
  private mp: number;
  private mpl: number;
  private mph: number;
  private um: number;
  private mt2: number;

  constructor(private m: BigInteger) {
    this.mp = m.invDigit();
    this.mpl = this.mp & 0x7fff;
    this.mph = this.mp >> 15;
    this.um = (1 << (m.DB - 15)) - 1;
    this.mt2 = 2 * m.t;
  }

  convert(x: BigInteger): BigInteger {
    const r = new BigInteger();
    x.abs().dlShiftTo(this.m.t, r);
    r.divRemTo(this.m, null, r);
    if (x.s < 0 && r.compareTo(BigInteger.ZERO) > 0) {
      this.m.subTo(r, r);
    }
    return r;
  }

  revert(x: BigInteger): BigInteger {
    const r = new BigInteger();
    x.copyTo(r);
    this.reduce(r);
    return r;
  }

  reduce(x: BigInteger): void {
    while (x.t <= this.mt2) {
      x.data[x.t++] = 0;
    }
    for (let i = 0; i < this.m.t; ++i) {
      let j = x.data[i] & 0x7fff;
      const u0 = (j * this.mpl + (((j * this.mph + (x.data[i] >> 15) * this.mpl) & this.um) << 15)) & x.DM;
      j = i + this.m.t;
      x.data[j] += this.m.am(0, u0, x, i, 0, this.m.t);
      while (x.data[j] >= x.DV) {
        x.data[j] -= x.DV;
        x.data[++j]++;
      }
    }
    x.clamp();
    x.drShiftTo(this.m.t, x);
    if (x.compareTo(this.m) >= 0) {
      x.subTo(this.m, x);
    }
  }

  mulTo(x: BigInteger, y: BigInteger, r: BigInteger): void {
    x.multiplyTo(y, r);
    this.reduce(r);
  }

  sqrTo(x: BigInteger, r: BigInteger): void {
    x.squareTo(r);
    this.reduce(r);
  }
}

class Barrett implements IReducer {
  private r2: BigInteger;
  private q3: BigInteger;
  private mu: BigInteger;

  constructor(private m: BigInteger) {
    this.r2 = new BigInteger();
    this.q3 = new BigInteger();
    BigInteger.ONE.dlShiftTo(2 * m.t, this.r2);
    this.mu = this.r2.divide(m);
  }

  convert(x: BigInteger): BigInteger {
    if (x.s < 0 || x.t > 2 * this.m.t) {
      return x.mod(this.m);
    } else if (x.compareTo(this.m) < 0) {
      return x;
    } else {
      const r = new BigInteger();
      x.copyTo(r);
      this.reduce(r);
      return r;
    }
  }

  revert(x: BigInteger): BigInteger {
    return x;
  }

  reduce(x: BigInteger): void {
    x.drShiftTo(this.m.t - 1, this.r2);
    if (x.t > this.m.t + 1) {
      x.t = this.m.t + 1;
      x.clamp();
    }
    this.mu.multiplyUpperTo(this.r2, this.m.t + 1, this.q3);
    this.m.multiplyLowerTo(this.q3, this.m.t + 1, this.r2);
    while (x.compareTo(this.r2) < 0) {
      x.dAddOffset(1, this.m.t + 1);
    }
    x.subTo(this.r2, x);
    while (x.compareTo(this.m) >= 0) {
      x.subTo(this.m, x);
    }
  }

  mulTo(x: BigInteger, y: BigInteger, r: BigInteger): void {
    x.multiplyTo(y, r);
    this.reduce(r);
  }

  sqrTo(x: BigInteger, r: BigInteger): void {
    x.squareTo(r);
    this.reduce(r);
  }
}
