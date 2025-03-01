import { describe, it, expect } from 'bun:test'
import { utils as UTIL } from 'ts-security-utils'
import { asn1 as ASN1 } from '../src/asn1'

describe('asn1', () => {
  // TODO: add more ASN.1 coverage

  it('should convert an OID to DER', () => {
    expect(ASN1.oidToDer('1.2.840.113549').toHex()).toBe('2a864886f70d')
  })

  it('should convert an OID from DER', () => {
    const der = UTIL.hexToBytes('2a864886f70d')
    expect(ASN1.derToOid(der)).toBe('1.2.840.113549')
  })

  it('should convert INTEGER 0 to DER', () => {
    expect(ASN1.integerToDer(0).toHex()).toBe('00')
  })

  it('should convert INTEGER 1 to DER', () => {
    expect(ASN1.integerToDer(1).toHex()).toBe('01')
  })

  it('should convert INTEGER 127 to DER', () => {
    expect(ASN1.integerToDer(127).toHex()).toBe('7f')
  })

  it('should convert INTEGER 128 to DER', () => {
    expect(ASN1.integerToDer(128).toHex()).toBe('0080')
  })

  it('should convert INTEGER 256 to DER', () => {
    expect(ASN1.integerToDer(256).toHex()).toBe('0100')
  })

  it('should convert INTEGER -128 to DER', () => {
    expect(ASN1.integerToDer(-128).toHex()).toBe('80')
  })

  it('should convert INTEGER -129 to DER', () => {
    expect(ASN1.integerToDer(-129).toHex()).toBe('ff7f')
  })

  it('should convert INTEGER 32768 to DER', () => {
    expect(ASN1.integerToDer(32768).toHex()).toBe('008000')
  })

  it('should convert INTEGER -32768 to DER', () => {
    expect(ASN1.integerToDer(-32768).toHex()).toBe('8000')
  })

  it('should convert INTEGER -32769 to DER', () => {
    expect(ASN1.integerToDer(-32769).toHex()).toBe('ff7fff')
  })

  it('should convert INTEGER 8388608 to DER', () => {
    expect(ASN1.integerToDer(8388608).toHex()).toBe('00800000')
  })

  it('should convert INTEGER -8388608 to DER', () => {
    expect(ASN1.integerToDer(-8388608).toHex()).toBe('800000')
  })

  it('should convert INTEGER -8388609 to DER', () => {
    expect(ASN1.integerToDer(-8388609).toHex()).toBe('ff7fffff')
  })

  it('should convert INTEGER 2147483647 to DER', () => {
    expect(ASN1.integerToDer(2147483647).toHex()).toBe('7fffffff')
  })

  it('should convert INTEGER -2147483648 to DER', () => {
    expect(ASN1.integerToDer(-2147483648).toHex()).toBe('80000000')
  })

  it('should convert INTEGER 0 from DER', () => {
    const der = UTIL.hexToBytes('00')
    expect(ASN1.derToInteger(der)).toBe(0)
  })

  it('should convert INTEGER 1 from DER', () => {
    const der = UTIL.hexToBytes('01')
    expect(ASN1.derToInteger(der)).toBe(1)
  })

  it('should convert INTEGER 127 from DER', () => {
    const der = UTIL.hexToBytes('7f')
    expect(ASN1.derToInteger(der)).toBe(127)
  })

  it('should convert INTEGER 128 from DER', () => {
    const der = UTIL.hexToBytes('0080')
    expect(ASN1.derToInteger(der)).toBe(128)
  })

  it('should convert INTEGER 256 from DER', () => {
    const der = UTIL.hexToBytes('0100')
    expect(ASN1.derToInteger(der)).toBe(256)
  })

  it('should convert INTEGER -128 from DER', () => {
    const der = UTIL.hexToBytes('80')
    expect(ASN1.derToInteger(der)).toBe(-128)
  })

  it('should convert INTEGER -129 from DER', () => {
    const der = UTIL.hexToBytes('ff7f')
    expect(ASN1.derToInteger(der)).toBe(-129)
  })

  it('should convert INTEGER 32768 from DER', () => {
    const der = UTIL.hexToBytes('008000')
    expect(ASN1.derToInteger(der)).toBe(32768)
  })

  it('should convert INTEGER -32768 from DER', () => {
    const der = UTIL.hexToBytes('8000')
    expect(ASN1.derToInteger(der)).toBe(-32768)
  })

  it('should convert INTEGER -32769 from DER', () => {
    const der = UTIL.hexToBytes('ff7fff')
    expect(ASN1.derToInteger(der)).toBe(-32769)
  })

  it('should convert INTEGER 8388608 from DER', () => {
    const der = UTIL.hexToBytes('00800000')
    expect(ASN1.derToInteger(der)).toBe(8388608)
  })

  it('should convert INTEGER -8388608 from DER', () => {
    const der = UTIL.hexToBytes('800000')
    expect(ASN1.derToInteger(der)).toBe(-8388608)
  })

  it('should convert INTEGER -8388609 from DER', () => {
    const der = UTIL.hexToBytes('ff7fffff')
    expect(ASN1.derToInteger(der)).toBe(-8388609)
  })

  it('should convert INTEGER 2147483647 from DER', () => {
    const der = UTIL.hexToBytes('7fffffff')
    expect(ASN1.derToInteger(der)).toBe(2147483647)
  })

  it('should convert INTEGER -2147483648 from DER', () => {
    const der = UTIL.hexToBytes('80000000')
    expect(ASN1.derToInteger(der)).toBe(-2147483648)
  })

  tests = [{
    in: '20110223123400',
    out: 1298464440000,
  }, {
    in: '20110223123400.1',
    out: 1298464440100,
  }, {
    in: '20110223123400.123',
    out: 1298464440123,
  }]
  tests.forEach((test) => {
    it(`should convert local generalized time "${test.in}" to a Date`, () => {
      const d = ASN1.generalizedTimeToDate(test.in)
      const localOffset = d.getTimezoneOffset() * 60000
      ASSERT.equal(d.getTime(), test.out + localOffset)
    })
  })

  tests = [{
    in: '20110223123400Z', // Wed Feb 23 12:34:00.000 UTC 2011
    out: 1298464440000,
  }, {
    in: '20110223123400.1Z', // Wed Feb 23 12:34:00.100 UTC 2011
    out: 1298464440100,
  }, {
    in: '20110223123400.123Z', // Wed Feb 23 12:34:00.123 UTC 2011
    out: 1298464440123,
  }, {
    in: '20110223123400+0200', // Wed Feb 23 10:34:00.000 UTC 2011
    out: 1298457240000,
  }, {
    in: '20110223123400.1+0200', // Wed Feb 23 10:34:00.100 UTC 2011
    out: 1298457240100,
  }, {
    in: '20110223123400.123+0200', // Wed Feb 23 10:34:00.123 UTC 2011
    out: 1298457240123,
  }, {
    in: '20110223123400-0200', // Wed Feb 23 14:34:00.000 UTC 2011
    out: 1298471640000,
  }, {
    in: '20110223123400.1-0200', // Wed Feb 23 14:34:00.100 UTC 2011
    out: 1298471640100,
  }, {
    in: '20110223123400.123-0200', // Wed Feb 23 14:34:00.123 UTC 2011
    out: 1298471640123,
  }]

  tests.forEach((test) => {
    it(`should convert utc generalized time "${test.in}" to a Date`, () => {
      const d = ASN1.generalizedTimeToDate(test.in)
      expect(d.getTime()).toBe(test.out)
    })
  })

  type TestData = {
    in: string
    out: string | number
  }

  let tests: TestData[] = [{
    in: 'Jan 1 1949 00:00:00 GMT',
    out: '19490101000000Z',
  }, {
    in: 'Jan 1 2000 00:00:00 GMT',
    out: '20000101000000Z',
  }, {
    in: 'Jan 1 2050 00:00:00 GMT',
    out: '20500101000000Z',
  }, {
    in: 'Mar 1 2100 00:00:00 GMT',
    out: '21000301000000Z',
  }]
  tests.forEach((test) => {
    it(`should convert date "${test.in}" to generalized time`, () => {
      const d = ASN1.dateToGeneralizedTime(new Date(test.in))
      expect(d).toBe(test.out)
    })
  })


  tests = [{
    in: '1102231234Z', // Wed Feb 23 12:34:00 UTC 2011
    out: 1298464440000,
  }, {
    in: '1102231234+0200', // Wed Feb 23 10:34:00 UTC 2011
    out: 1298457240000,
  }, {
    in: '1102231234-0200', // Wed Feb 23 14:34:00 UTC 2011
    out: 1298471640000,
  }, {
    in: '110223123456Z', // Wed Feb 23 12:34:56 UTC 2011
    out: 1298464496000,
  }, {
    in: '110223123456+0200', // Wed Feb 23 10:34:56 UTC 2011
    out: 1298457296000,
  }, {
    in: '110223123456-0200', // Wed Feb 23 14:34:56 UTC 2011
    out: 1298471696000,
  }, {
    in: '500101000000Z',
    out: -631152000000,
  }]
  tests.forEach((test) => {
    it(`should convert utc time "${test.in}" to a Date`, () => {
      const d = ASN1.utcTimeToDate(test.in)
      expect(d.getTime()).toBe(test.out)
    })
  })

  tests = [{
    in: 'Sat Dec 31 1949 19:00:00 GMT-0500',
    out: '500101000000Z',
  }]
  tests.forEach((test) => {
    it(`should convert date "${test.in}" to utc time`, () => {
      const d = ASN1.dateToUtcTime(new Date(test.in))
      expect(d).toBe(test.out)
    })
  })

  // use function to avoid calling apis during setup
  function _asn1(str) {
    return function () {
      return ASN1.fromDer(UTIL.hexToBytes(str.replace(/ /g, '')))
    }
  }
  tests = [{
    name: 'empty strings',
    obj1: '',
    obj2: '',
    equal: true,
  }, {
    name: 'simple strings',
    obj1: '\u0001',
    obj2: '\u0001',
    equal: true,
  }, {
    name: 'simple strings',
    obj1: '\u0000',
    obj2: '\u0001',
    equal: false,
  }, {
    name: 'simple arrays',
    obj1: ['', ''],
    obj2: ['', ''],
    equal: true,
  }, {
    name: 'simple arrays',
    obj1: ['', ''],
    obj2: [''],
    equal: false,
  }, {
    name: 'INTEGERs',
    obj1: _asn1('02 01 00'),
    obj2: _asn1('02 01 00'),
    equal: true,
  }, {
    name: 'BER INTEGERs',
    obj1: _asn1('02 01 01'),
    obj2: _asn1('02 02 00 01'),
    equal: false,
  }, {
    name: 'BIT STRINGs',
    obj1: _asn1('03 02 00 01'),
    obj2: _asn1('03 02 00 01'),
    equal: true,
  }, {
    name: 'BIT STRINGs',
    obj1: _asn1('03 02 00 01'),
    obj2: _asn1('03 02 00 02'),
    equal: false,
  }, {
    name: 'BIT STRINGs sub INTEGER',
    obj1: _asn1('03 04 00 02 01 01'),
    obj2: _asn1('03 04 00 02 01 01'),
    equal: true,
  }, {
    name: 'mutated BIT STRINGs',
    obj1: _asn1('03 04 00 02 01 01'),
    obj2: _asn1('03 04 00 02 01 01'),
    mutate(obj1, obj2) {
      obj2.value[0].value = '\u0002'
    },
    equal: false,
  }]
  tests.forEach((test, index) => {
    const name = `should check ASN.1 ${
      test.equal ? '' : 'not '}equal: ${
      test.name || `#${index}`}`
    it(name, () => {
      const obj1 = typeof test.obj1 === 'function' ? test.obj1() : test.obj1
      const obj2 = typeof test.obj2 === 'function' ? test.obj2() : test.obj2
      if (test.mutate) {
        test.mutate(obj1, obj2)
      }
      expect(ASN1.equals(obj1, obj2)).toBe(test.equal)
    })
  })

  tests = [{
    name: 'empty string',
    obj: '',
  }, {
    name: 'simple string',
    obj: '\u0001',
  }, {
    name: 'simple array',
    obj: ['', ''],
  }, {
    name: 'INTEGER',
    obj: _asn1('02 01 00'),
  }, {
    name: 'BER INTEGER',
    obj: _asn1('02 01 01'),
  }, {
    name: 'BIT STRING',
    obj: _asn1('03 02 00 01'),
  }, {
    name: 'BIT STRING sub INTEGER',
    obj: _asn1('03 04 00 02 01 01'),
  }]
  tests.forEach((test, index) => {
    const name = `should check ASN.1 copy: ${test.name || `#${index}`}`
    it(name, () => {
      const obj = typeof test.obj === 'function' ? test.obj() : test.obj
      expect(ASN1.equals(ASN1.copy(obj), obj)).toBe(true)
    })
  })

  function _h2b(str) {
    return UTIL.hexToBytes(str.replace(/ /g, ''))
  }
  function _add(b, str) {
    b.putBytes(_h2b(str))
  }
  function _asn1dump(asn1: any) {
    console.log(ASN1.prettyPrint(asn1))
    console.log(JSON.stringify(asn1, null, 2))
  }
  function _asn1TestOne(strict: boolean, throws: boolean, options: any) {
    options = options || {}
    if (!('decodeBitStrings' in options)) {
      options.decodeBitStrings = true
    }
    // buffer strict test
    const b = UTIL.createBuffer()
    // init
    options.init(b)
    // bytes for round-trip comparison
    const bytes = b.copy().bytes()
    // copy for non-strict test
    const bns = b.copy()
    // create strict and non-strict asn1
    const asn1assert = throws ? ASSERT.throws : function (f) { f() }
    let asn1
    let der
    asn1assert(() => {
      asn1 = ASN1.fromDer(b, {
        strict,
        decodeBitStrings: options.decodeBitStrings,
      })
    })
    // debug
    if (options.dump && asn1) {
      console.log(`=== ${strict ? 'Strict' : 'Non Strict'} ===`)
      _asn1dump(asn1)
    }
    // basic check
    if (!throws) {
      ASSERT.ok(asn1)
    }

    // round-trip(ish) check
    if (!throws) {
      der = ASN1.toDer(asn1)
      if (options.roundtrip) {
        // byte comparisons for round-trip testing can fail due to
        // semantically safe changes such as changing the length encoding.
        // test a roundtrip for data where it makes sense.
        expect(UTIL.bytesToHex(bytes)).toBe(UTIL.bytesToHex(der.bytes()))
      }
    }

    // validator check
    if (!throws && options.v) {
      const capture = {}
      const errors = []
      const asn1ok = ASN1.validate(asn1, options.v, capture, errors)
      expect(errors).toEqual([])
      if (options.captured) {
        expect(capture).toEqual(options.captured)
      }
      else {
        expect(capture).toEqual({})
      }
      expect(asn1ok).toBe(true)
    }

    return {
      asn1,
      der,
    }
  }
  function _asn1Test(options) {
    const s = _asn1TestOne(true, options.strictThrows, options)
    const ns = _asn1TestOne(false, options.nonStrictThrows, options)

    // check asn1 equality
    if (s.asn1 && ns.asn1) {
      expect(s.asn1).toEqual(ns.asn1)
    }

    // check der equality
    if (s.der && ns.der) {
      expect(UTIL.bytesToHex(s.der.bytes())).toBe(UTIL.bytesToHex(ns.der.bytes()))
    }

    if (options.done) {
      options.done({
        strict: s,
        nonStrict: ns,
      })
    }
  }

  it('should convert BIT STRING from DER (short,empty)', () => {
    _asn1Test({
      init(b: Buffer) {
        // BIT STRING value=none
        _add(b, '03 00')
      },
      dump: false,
      roundtrip: true,
      v: {
        tagClass: ASN1.Class.UNIVERSAL,
        type: ASN1.Type.BITSTRING,
        constructed: false,
        captureBitStringContents: 'bits',
      },
      captured: {
        bits: '',
      },
    })
  })

  it('should convert BIT STRING from DER (short,empty2)', () => {
    _asn1Test({
      init(b: Buffer) {
        // BIT STRING value=none
        _add(b, '03 01 00')
      },
      dump: false,
      roundtrip: true,
      v: {
        tagClass: ASN1.Class.UNIVERSAL,
        type: ASN1.Type.BITSTRING,
        constructed: false,
        captureBitStringContents: 'bitsC',
        captureBitStringValue: 'bitsV',
      },
      captured: {
        bitsC: _h2b('00'),
        bitsV: '',
      },
    })
  })

  it('should convert BIT STRING from BER (short,invalid)', () => {
    _asn1Test({
      init(b: Buffer) {
        // BIT STRING value=partial
        // invalid in strict mode, non-strict will read 1 of 2 bytes
        _add(b, '03 02 00')
      },
      dump: false,
      roundtrip: false,
      strictThrows: true,
      nonStrictThrows: false,
      v: {
        tagClass: ASN1.Class.UNIVERSAL,
        type: ASN1.Type.BITSTRING,
        constructed: false,
        captureBitStringContents: 'bits',
      },
      captured: {
        // only for non-strict mode, truncated value
        bits: _h2b('00'),
      },
    })
  })

  it('should convert BIT STRING from DER (short)', () => {
    _asn1Test({
      init(b: Buffer) {
        // BIT STRING value=0110111001011101
        _add(b, '03 03 00 6e 5d')
      },
      dump: false,
      roundtrip: true,
      v: {
        tagClass: ASN1.Class.UNIVERSAL,
        type: ASN1.Type.BITSTRING,
        constructed: false,
        captureBitStringContents: 'bits',
      },
      captured: {
        bits: _h2b('00 6e 5d'),
      },
    })
  })

  it('should convert BIT STRING from DER (short2)', () => {
    _asn1Test({
      init(b: Buffer) {
        // BIT STRING value=0110111001011101
        // contains an INTEGER=0x12
        _add(b, '03 04 00 02 01 12')
      },
      dump: false,
      roundtrip: true,
      v: {
        tagClass: ASN1.Class.UNIVERSAL,
        type: ASN1.Type.BITSTRING,
        constructed: false,
        // note captureBitStringContents used to get all bytes
        // 'capture' would get the value structure
        // 'captureAsn1' would get the value and sub-value structures
        captureBitStringContents: 'bits',
        value: [{
          tagClass: ASN1.Class.UNIVERSAL,
          type: ASN1.Type.INTEGER,
          constructed: false,
          capture: 'int0',
        }],
      },
      captured: {
        bits: _h2b('00 02 01 12'),
        int0: _h2b('12'),
      },
    })
  })

  it('should convert BIT STRING from DER (short,unused1z)', () => {
    _asn1Test({
      init(b: Buffer) {
        // BIT STRING value=01101110010111011010111, unused=0
        _add(b, '03 04 01 6e 5d ae')
      },
      dump: false,
      roundtrip: true,
      v: {
        tagClass: ASN1.Class.UNIVERSAL,
        type: ASN1.Type.BITSTRING,
        constructed: false,
        captureBitStringContents: 'bits',
      },
      captured: {
        bits: _h2b('01 6e 5d ae'),
      },
    })
  })

  it('should convert BIT STRING from DER (short,unused6z)', () => {
    _asn1Test({
      init(b: Buffer) {
        // BIT STRING short len, value=011011100101110111, unused=000000
        _add(b, '03 04 06 6e 5d c0')
      },
      dump: false,
      roundtrip: true,
      v: {
        tagClass: ASN1.Class.UNIVERSAL,
        type: ASN1.Type.BITSTRING,
        constructed: false,
        captureBitStringContents: 'bits',
      },
      captured: {
        bits: _h2b('06 6e 5d c0'),
      },
    })
  })

  it('should convert BIT STRING from BER (short,unused6d)', () => {
    _asn1Test({
      init(b: Buffer) {
        // BIT STRING short len, value=011011100101110111, unused=100000
        _add(b, '03 04 06 6e 5d e0')
      },
      dump: false,
      roundtrip: true,
      v: {
        tagClass: ASN1.Class.UNIVERSAL,
        type: ASN1.Type.BITSTRING,
        constructed: false,
        captureBitStringContents: 'bits',
      },
      captured: {
        bits: _h2b('06 6e 5d e0'),
      },
    })
  })

  it('should convert BIT STRING from BER (long,unused6z)', () => {
    _asn1Test({
      init(b: Buffer) {
        // BIT STRING long len, value=011011100101110111, unused=000000
        _add(b, '03 81 04 06 6e 5d c0')
      },
      dump: false,
      // length is compressed
      roundtrip: false,
      v: {
        tagClass: ASN1.Class.UNIVERSAL,
        type: ASN1.Type.BITSTRING,
        constructed: false,
        captureBitStringContents: 'bits',
      },
      captured: {
        bits: _h2b('06 6e 5d c0'),
      },
    })
  })

  it('should convert BIT STRING from BER (unused6z)', () => {
    _asn1Test({
      init(b: Buffer) {
        // BIT STRING constructed, value=0110111001011101+11, unused=000000
        _add(b, '23 09')
        _add(b, '03 03 00 6e 5d')
        _add(b, '03 02 06 c0')
      },
      dump: false,
      roundtrip: true,
      v: {
        tagClass: ASN1.Class.UNIVERSAL,
        type: ASN1.Type.BITSTRING,
        constructed: true,
        value: [{
          tagClass: ASN1.Class.UNIVERSAL,
          type: ASN1.Type.BITSTRING,
          constructed: false,
          capture: 'bits0',
        }, {
          tagClass: ASN1.Class.UNIVERSAL,
          type: ASN1.Type.BITSTRING,
          constructed: false,
          capture: 'bits1',
        }],
      },
      captured: {
        bits0: _h2b('00 6e 5d'),
        bits1: _h2b('06 c0'),
      },
    })
  })

  it('should convert BIT STRING from BER (decode)', () => {
    _asn1Test({
      init(b: Buffer) {
        // create crafted DER BIT STRING data that includes encapsulated
        // data.  often used to store SEQUENCE of INTEGERs.
        // add bit stream of bytes using long length
        _add(b, '03 82 00 10')
        // no padding
        _add(b, '00')
        // sequence of two ints
        _add(b, '30 0D')
        // add test int, long len
        _add(b, '02 81 04 12 34 56 78')
        // add test int, short len
        _add(b, '02 04 87 65 43 21')
      },
      dump: false,
      decodeBitStrings: true,
      // long len will compress to short len
      roundtrip: false,
      v: {
        tagClass: ASN1.Class.UNIVERSAL,
        type: ASN1.Type.BITSTRING,
        constructed: false,
        captureBitStringContents: 'bits',
        value: [{
          tagClass: ASN1.Class.UNIVERSAL,
          type: ASN1.Type.SEQUENCE,
          constructed: true,
          value: [{
            tagClass: ASN1.Class.UNIVERSAL,
            type: ASN1.Type.INTEGER,
            constructed: false,
            capture: 'int0',
          }, {
            tagClass: ASN1.Class.UNIVERSAL,
            type: ASN1.Type.INTEGER,
            constructed: false,
            capture: 'int1',
          }],
        }],
      },
      captured: {
        bits: _h2b(
          '00'
          + '30 0D'
          + '02 81 04 12 34 56 78'
          + '02 04 87 65 43 21',
        ),
        int0: _h2b('12 34 56 78'),
        int1: _h2b('87 65 43 21'),
      },
    })
  })

  it('should convert BIT STRING from BER (no decode)', () => {
    _asn1Test({
      init(b: Buffer) {
        // create crafted DER BIT STRING data that includes encapsulated
        // data.  often used to store SEQUENCE of INTEGERs.
        // add bit stream
        _add(b, '03 82 00 10')
        // no padding
        _add(b, '00')
        // sequence of two ints
        _add(b, '30 0D')
        // add test int, long len
        _add(b, '02 81 04 12 34 56 78')
        // add test int, short len
        _add(b, '02 04 87 65 43 21')
      },
      dump: false,
      decodeBitStrings: false,
      // long length is compressed
      roundtrip: false,
      v: {
        tagClass: ASN1.Class.UNIVERSAL,
        type: ASN1.Type.BITSTRING,
        constructed: false,
        captureBitStringContents: 'bits',
      },
      captured: {
        bits: _h2b(
          '00'
          + '30 0D'
          + '02 81 04 12 34 56 78'
          + '02 04 87 65 43 21',
        ),
      },
    })
  })

  it('should convert BIT STRING from DER (decode2)', () => {
    _asn1Test({
      init(b: Buffer) {
        // create crafted DER BIT STRING data that includes encapsulated
        // data.  often used to store SEQUENCE of INTEGERs.
        // bit stream
        _add(b, '03 81 8D')
        // no padding
        _add(b, '00')
        // sequence
        _add(b, '30 81 89')
        // int header and leading 0
        _add(b, '02 81 81 00')
        // 1024 bit int
        _add(b, 'FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF F0')
        _add(b, 'FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF F1')
        _add(b, 'FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF F2')
        _add(b, 'FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF F3')
        _add(b, 'FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF F4')
        _add(b, 'FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF F5')
        _add(b, 'FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF F6')
        _add(b, 'FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF F7')
        // int header and 3 byte int
        _add(b, '02 03 01 00 01')
      },
      dump: false,
      decodeBitStrings: true,
      roundtrip: true,
      v: {
        tagClass: ASN1.Class.UNIVERSAL,
        type: ASN1.Type.BITSTRING,
        constructed: false,
        value: [{
          tagClass: ASN1.Class.UNIVERSAL,
          type: ASN1.Type.SEQUENCE,
          constructed: true,
          value: [{
            tagClass: ASN1.Class.UNIVERSAL,
            type: ASN1.Type.INTEGER,
            constructed: false,
            capture: 'int0',
          }, {
            tagClass: ASN1.Class.UNIVERSAL,
            type: ASN1.Type.INTEGER,
            constructed: false,
            capture: 'int1',
          }],
        }],
      },
      captured: {
        int0: _h2b('00'
          + 'FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF F0'
          + 'FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF F1'
          + 'FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF F2'
          + 'FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF F3'
          + 'FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF F4'
          + 'FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF F5'
          + 'FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF F6'
          + 'FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF F7'),
        int1: _h2b('01 00 01'),
      },
    })
  })

  it('should convert BIT STRING from DER (sig)', () => {
    _asn1Test({
      init(b: Buffer) {
        // create crafted DER BIT STRING data similar to a signature that
        // could be interpreted incorrectly as encapsulated data.
        // add bit stream of 257 bytes
        _add(b, '03 82 01 01')
        // no unused
        _add(b, '00')
        // signature bits
        _add(b, '25 81 FD 6E D3 AB 34 45 DE AE F1 5B EC 6A FB 79')
        _add(b, '14 CD 7B B2 8E 48 59 AE 89 B1 55 60 11 AB BC 7F')
        _add(b, '6D 6D FE 16 22 42 AC 57 CC E9 C0 3A 8D 1E F3 C3')
        _add(b, '97 C8 23 53 DE E0 34 C3 A9 43 8B 2B D9 C0 24 FF')
        _add(b, 'FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF F4')
        _add(b, 'FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF F5')
        _add(b, 'FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF F6')
        _add(b, 'FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF F7')
        _add(b, 'FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF F8')
        _add(b, 'FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF F9')
        _add(b, 'FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FA')
        _add(b, 'FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FB')
        _add(b, 'FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FC')
        _add(b, 'FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FD')
        _add(b, 'FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FE')
        _add(b, 'FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF')
      },
      dump: false,
      roundtrip: true,
      v: {
        tagClass: ASN1.Class.UNIVERSAL,
        type: ASN1.Type.BITSTRING,
        constructed: false,
        // captureBitStringContents not used to check if value decoded
        capture: 'sig',
      },
      captured: {
        sig: _h2b(
          '00'
          + '25 81 FD 6E D3 AB 34 45 DE AE F1 5B EC 6A FB 79'
          + '14 CD 7B B2 8E 48 59 AE 89 B1 55 60 11 AB BC 7F'
          + '6D 6D FE 16 22 42 AC 57 CC E9 C0 3A 8D 1E F3 C3'
          + '97 C8 23 53 DE E0 34 C3 A9 43 8B 2B D9 C0 24 FF'
          + 'FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF F4'
          + 'FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF F5'
          + 'FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF F6'
          + 'FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF F7'
          + 'FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF F8'
            + 'FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF F9'
            + 'FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FA'
            + 'FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FB'
            + 'FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FC'
            + 'FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FD'
            + 'FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FE'
            + 'FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF',
        ),
      },
    })
  })

  it('should convert BIT STRING from DER (sig2)', () => {
    _asn1Test({
      init(b: Buffer) {
        // create crafted DER BIT STRING data similar to a signature that
        // could be interpreted incorrectly as encapsulated data.
        // add bit stream of 257 bytes
        _add(b, '03 82 01 01')
        // no unused
        _add(b, '00')
        // signature bits
        _add(b, '2B 05 9D 81 FB 07 2C CE 15 0A 39 CD D3 89 A7 83')
        _add(b, '5C 99 5E B2 0D A4 E0 26 81 20 EF 5A 0F 23 46 E0')
        _add(b, '46 4A 5D 7B 6A C9 4F B1 38 D5 FC 71 6A 32 06 6C')
        _add(b, '68 15 9E F2 13 DB 2A 36 41 93 51 4C 98 EB 9F 32')
        _add(b, '28 54 07 CE B2 05 92 A7 C8 DF 2F A1 E3 C9 9C 0A')
        _add(b, 'E4 BE B3 88 17 CF 62 70 80 CD 10 B8 9B 08 E0 47')
        _add(b, '61 24 12 16 C0 FC 70 D9 0A 4A 39 09 F4 51 F1 62')
        _add(b, '0A 56 6B 46 C1 E2 0B FF 92 3E F5 A5 06 EE 55 0A')
        _add(b, '6D FD DA 18 B9 C1 30 6E 98 CD 38 4D 9C C5 B5 6B')
        _add(b, '81 19 B7 B1 19 52 5C F8 99 9D C2 EC A1 F5 96 A7')
        _add(b, '66 79 A6 53 F8 17 67 64 52 F6 32 37 F4 CD 74 5A')
        _add(b, '2F 59 35 06 90 6B CC F7 E6 7D 67 C4 FA 0C 7B 10')
        _add(b, '05 85 E8 4F E2 0E EF A0 D4 F8 57 EB BF 2F 14 42')
        _add(b, '62 01 09 08 35 5C 24 8C 0D 5D FD FA 52 58 D8 C9')
        _add(b, '10 45 4F AE 15 B0 9A 82 B9 FB 17 CC E6 A0 BD BA')
        _add(b, '76 BD 05 F1 70 69 43 9D 60 31 F9 F4 13 7A 8C 71')
      },
      dump: false,
      roundtrip: true,
      v: {
        tagClass: ASN1.Class.UNIVERSAL,
        type: ASN1.Type.BITSTRING,
        constructed: false,
        // captureBitStringContents not used to check if value decoded
        captureBitStringValue: 'bits',
      },
      captured: {
        bits: _h2b(
          '2B 05 9D 81 FB 07 2C CE 15 0A 39 CD D3 89 A7 83'
          + '5C 99 5E B2 0D A4 E0 26 81 20 EF 5A 0F 23 46 E0'
          + '46 4A 5D 7B 6A C9 4F B1 38 D5 FC 71 6A 32 06 6C'
          + '68 15 9E F2 13 DB 2A 36 41 93 51 4C 98 EB 9F 32'
          + '28 54 07 CE B2 05 92 A7 C8 DF 2F A1 E3 C9 9C 0A'
          + 'E4 BE B3 88 17 CF 62 70 80 CD 10 B8 9B 08 E0 47'
          + '61 24 12 16 C0 FC 70 D9 0A 4A 39 09 F4 51 F1 62'
          + '0A 56 6B 46 C1 E2 0B FF 92 3E F5 A5 06 EE 55 0A'
          + '6D FD DA 18 B9 C1 30 6E 98 CD 38 4D 9C C5 B5 6B'
          + '81 19 B7 B1 19 52 5C F8 99 9D C2 EC A1 F5 96 A7'
            + '66 79 A6 53 F8 17 67 64 52 F6 32 37 F4 CD 74 5A'
            + '2F 59 35 06 90 6B CC F7 E6 7D 67 C4 FA 0C 7B 10'
            + '05 85 E8 4F E2 0E EF A0 D4 F8 57 EB BF 2F 14 42'
            + '62 01 09 08 35 5C 24 8C 0D 5D FD FA 52 58 D8 C9'
            + '10 45 4F AE 15 B0 9A 82 B9 FB 17 CC E6 A0 BD BA'
            + '76 BD 05 F1 70 69 43 9D 60 31 F9 F4 13 7A 8C 71',
        ),
      },
    })
  })

  it('should convert BIT STRING from DER (sig3)', () => {
    _asn1Test({
      init(b: Buffer) {
        // create crafted DER BIT STRING data similar to a signature that
        // could be interpreted incorrectly as encapsulated data.
        _add(b, '03 0B')
        // no unused
        _add(b, '00')
        // signature bits with structure with bad type and length
        _add(b, '2B 05 9D 05 F0 F1 F2 F3 F4 F5')
      },
      dump: false,
      roundtrip: true,
      v: {
        tagClass: ASN1.Class.UNIVERSAL,
        type: ASN1.Type.BITSTRING,
        constructed: false,
        // captureBitStringContents not used to check if value decoded
        capture: 'sig',
      },
      captured: {
        sig: _h2b(
          '00'
          + '2B 05 9D 05 F0 F1 F2 F3 F4 F5',
        ),
      },
    })
  })

  it('should convert BIT STRING from BER (decodable sig)', () => {
    _asn1Test({
      init(b: Buffer) {
        // create crafted DER BIT STRING data similar to a signature that
        // could be interpreted as encapsulated data. data is such that
        // a round trip process could change the data due to INTEGER
        // optimization (removal of leading bytes) or length structure
        // compression (long to short).
        // add a basic bit stream "signature" with test data
        _add(b, '03 22')
        // no unused
        _add(b, '00')
        // everything after this point might be important bits, not ASN.1
        // SEQUENCE of tests
        _add(b, '30 1E')
        // signature bits
        // '02 02' prefix will be cause parsing as an integer
        // toDer will try to remove the extra 00.
        // tests the BIT STRING content/value saving feature
        _add(b, '02 02 00 7F')
        // similar example for -1:
        _add(b, '02 02 FF FF')
        // could extend out to any structure size:
        _add(b, '02 06 FF FF FF FF FF FF')
        // the roundtrip issue can exist for long lengths that could
        // compress to short lengths, this could be output as '02 02 01 23':
        _add(b, '02 81 02 01 23')
        // also an issue for indefinite length structures that will
        // have a known length later:
        _add(b, '30 80')
        // a few INTEGERs
        _add(b, '02 01 00')
        _add(b, '02 01 01')
        // done
        _add(b, '00 00')
        // other examples may exist
      },
      dump: false,
      // NOTE: arbitrary data can be compacted, check saved data worked
      roundtrip: true,
      v: {
        tagClass: ASN1.Class.UNIVERSAL,
        type: ASN1.Type.BITSTRING,
        constructed: false,
        captureBitStringValue: 'sig',
      },
      captured: {
        sig: _h2b(
          '30 1E'
          + '02 02 00 7F'
          + '02 02 FF FF'
          + '02 06 FF FF FF FF FF FF'
          + '02 81 02 01 23'
          + '30 80'
          + '02 01 00'
          + '02 01 01'
          + '00 00',
        ),
      },
    })
  })

  it('should convert BIT STRING from strict DER', () => {
    _asn1Test({
      init(b: Buffer) {
        // create crafted DER BIT STRING data that includes encapsulated
        // data.  include valid data that would only parse in strict
        // mode.
        _add(b, '03 06')
        // no padding
        _add(b, '00')
        // sub-BIT STRING with valid length
        _add(b, '03 03 00 01 02')
      },
      dump: false,
      decodeBitStrings: true,
      roundtrip: true,
      v: {
        tagClass: ASN1.Class.UNIVERSAL,
        type: ASN1.Type.BITSTRING,
        constructed: false,
        // default capture value has structural data
        // check contents and value
        captureBitStringContents: 'bitsC',
        captureBitStringValue: 'bitsV',
      },
      captured: {
        bitsC: _h2b('00 03 03 00 01 02'),
        bitsV: _h2b('03 03 00 01 02'),
      },
    })
  })
  it('should convert BIT STRING from non-strict DER', () => {
    _asn1Test({
      init(b: Buffer) {
        // create crafted DER BIT STRING data that includes encapsulated
        // data.  include invalid data that would only parse in non-strict
        // mode.  ensure it is never parsed.
        _add(b, '03 05')
        // no padding
        _add(b, '00')
        // sub-BIT STRING with invalid length, missing a byte
        _add(b, '03 03 00 01')
      },
      dump: false,
      decodeBitStrings: true,
      roundtrip: true,
      v: {
        tagClass: ASN1.Class.UNIVERSAL,
        type: ASN1.Type.BITSTRING,
        constructed: false,
        // ensure default captures contents vs decoded structure
        capture: 'bits0',
        // check contents and value
        captureBitStringContents: 'bitsC',
        captureBitStringValue: 'bitsV',
      },
      captured: {
        bits0: _h2b('00 03 03 00 01'),
        bitsC: _h2b('00 03 03 00 01'),
        bitsV: _h2b('03 03 00 01'),
      },
    })
  })

  it('should convert indefinite length seq from BER', () => {
    _asn1Test({
      init(b: Buffer) {
        // SEQUENCE
        _add(b, '30 80')
        // a few INTEGERs
        _add(b, '02 01 00')
        _add(b, '02 01 01')
        _add(b, '02 01 02')
        // done
        _add(b, '00 00')
      },
      dump: false,
      // roundtrip will know the sequence length
      roundtrip: false,
      v: {
        tagClass: ASN1.Class.UNIVERSAL,
        type: ASN1.Type.SEQUENCE,
        constructed: true,
        value: [{
          tagClass: ASN1.Class.UNIVERSAL,
          type: ASN1.Type.INTEGER,
          constructed: false,
          capture: 'int0',
        }, {
          tagClass: ASN1.Class.UNIVERSAL,
          type: ASN1.Type.INTEGER,
          constructed: false,
          capture: 'int1',
        }, {
          tagClass: ASN1.Class.UNIVERSAL,
          type: ASN1.Type.INTEGER,
          constructed: false,
          capture: 'int2',
        }],
      },
      captured: {
        int0: _h2b('00'),
        int1: _h2b('01'),
        int2: _h2b('02'),
      },
    })
  })

  it('should handle ASN.1 mutations', () => {
    _asn1Test({
      init(b: Buffer) {
        // BIT STRING
        _add(b, '03 09 00')
        // SEQUENCE
        _add(b, '30 06')
        // a few INTEGERs
        _add(b, '02 01 00')
        _add(b, '02 01 01')
      },
      dump: false,
      // roundtrip will know the sequence length
      roundtrip: true,
      v: {
        tagClass: ASN1.Class.UNIVERSAL,
        type: ASN1.Type.BITSTRING,
        constructed: false,
        captureBitStringContents: 'bits',
        value: [{
          tagClass: ASN1.Class.UNIVERSAL,
          type: ASN1.Type.SEQUENCE,
          constructed: true,
          value: [{
            tagClass: ASN1.Class.UNIVERSAL,
            type: ASN1.Type.INTEGER,
            constructed: false,
            capture: 'int0',
          }, {
            tagClass: ASN1.Class.UNIVERSAL,
            type: ASN1.Type.INTEGER,
            constructed: false,
            capture: 'int1',
          }],
        }],
      },
      captured: {
        bits: _h2b('00 30 06 02 01 00 02 01 01'),
        int0: _h2b('00'),
        int1: _h2b('01'),
      },
      done(data) {
        const asn1 = data.strict.asn1
        // mutate
        asn1.value[0].value[0].value = _h2b('02')
        asn1.value[0].value[1].value = _h2b('03')
        // convert
        // must use new data vs saved BIT STRING data
        const der = ASN1.toDer(asn1)
        const expected = _h2b('03 09 00 30 06 02 01 02 02 01 03')
        // compare
        expect(UTIL.bytesToHex(der)).toBe(UTIL.bytesToHex(expected))
      },
    })
  })

  it('should convert BMP STRING from DER', () => {
    _asn1Test({
      init(b: Buffer) {
        // BPMSTRING
        _add(b, '1e 08')
        _add(b, '01 02 03 04 05 06 07 08')
      },
      dump: false,
      roundtrip: true,
      v: {
        tagClass: ASN1.Class.UNIVERSAL,
        type: ASN1.Type.BPMSTRING,
        constructed: false,
        capture: 'bits',
      },
      captured: {
        bits: '\u0102\u0304\u0506\u0708',
      },
    })
  })

  // TODO: how minimal should INTEGERs be encoded?
  // .. fromDer will create the full integer
  // .. toDer will remove only first byte if possible
  it('should minimally encode INTEGERs', () => {
    function _test(hin: string, hout: string) {
      const derIn = _h2b(hin)
      const derOut = ASN1.toDer(ASN1.fromDer(derIn))
      expect(UTIL.bytesToHex(derOut)).toBe(UTIL.bytesToHex(_h2b(hout)))
    }

    // optimal
    _test('02 01 01', '02 01 01')
    _test('02 01 FF', '02 01 FF')
    _test('02 02 00 FF', '02 02 00 FF')

    // remove leading 00s before a 0b0xxxxxxx
    _test('02 04 00 00 00 01', '02 03 00 00 01')
    // this would be more optimal
    // _test('02 04 00 00 00 01', '02 01 01');

    // remove leading FFs before a 0b1xxxxxxx
    _test('02 04 FF FF FF FF', '02 03 FF FF FF')
    // this would be more optimal
    // _test('02 04 FF FF FF FF', '02 01 FF');
  })
})
