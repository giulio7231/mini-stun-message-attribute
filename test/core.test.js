import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  parseAttribute,
  serializeAttribute,
  parseXorMappedAddress,
  serializeXorMappedAddress,
  STUN_ATTRIBUTE_TYPE,
  MAGIC_COOKIE,
  parseIPv6,
  formatIPv6,
} from '../src/index.js';

// --- parseAttribute / serializeAttribute round trips ---

test('serializeAttribute pads to 4-byte boundary with zero bytes', () => {
  const value = Buffer.from([0xaa, 0xbb, 0xcc]); // length 3 → pad 1
  const out = serializeAttribute(0x0001, value);
  assert.equal(out.length, 8);
  assert.equal(out.readUInt16BE(0), 0x0001);
  assert.equal(out.readUInt16BE(2), 3);
  assert.deepEqual(Array.from(out.subarray(4, 7)), [0xaa, 0xbb, 0xcc]);
  assert.equal(out[7], 0x00); // padding
});

(test)('serializeAttribute needs no padding when value length is a multiple of 4', () => {
  const value = Buffer.from([1, 2, 3, 4]);
  const out = serializeAttribute(0x0020, value);
  assert.equal(out.length, 8);
  assert.equal(out.readUInt16BE(2), 4);
});

test('serializeAttribute rejects out-of-range type', () => {
  assert.throws(() => serializeAttribute(0x10000, Buffer.alloc(0)), /type/);
});

test('serializeAttribute rejects non-Buffer value', () => {
  assert.throws(() => serializeAttribute(0x0001, 'oops'), /Buffer/);
});

test('parseAttribute round-trips a padded attribute', () => {
  const value = Buffer.from([0xde, 0xad, 0xbe, 0xef]);
  const serialized = serializeAttribute(0x0001, value);
  const parsed = parseAttribute(serialized);
  assert.equal(parsed.type, 0x0001);
  assert.equal(parsed.length, 4);
  assert.deepEqual(Array.from(parsed.value), [0xde, 0xad, 0xbe, 0xef]);
  assert.equal(parsed.raw.length, 8);
});

test('parseAttribute respects offset argument', () => {
  const value = Buffer.from([0x01, 0x02]);
  const serialized = serializeAttribute(0x0009, value); // length 2 → pad 2 → total 8
  const withPrefix = Buffer.concat([Buffer.from([0xff, 0xff]), serialized]);
  const parsed = parseAttribute(withPrefix, 2);
  assert.equal(parsed.type, 0x0009);
  assert.equal(parsed.length, 2);
  assert.deepEqual(Array.from(parsed.value), [0x01, 0x02]);
});

test('parseAttribute throws on truncated header', () => {
  assert.throws(() => parseAttribute(Buffer.from([0x00, 0x01])), /truncated/);
});

test('parseAttribute throws when value length exceeds buffer', () => {
  // type=0x0001, length=0x0010 (16) but only 2 bytes follow
  const buf = Buffer.from([0x00, 0x01, 0x00, 0x10, 0xaa, 0xbb]);
  assert.throws(() => parseAttribute(buf), /truncated/);
});

test('parseAttribute throws on non-Buffer input', () => {
  assert.throws(() => parseAttribute('nope'), /Buffer/);
  assert.throws(() => parseAttribute(Buffer.alloc(8), -1), /offset/);
});

// --- XOR-MAPPED-ADDRESS IPv4 ---

test('XOR-MAPPED-ADDRESS IPv4 round-trips', () => {
  const ip = '192.0.2.1';
  const port = 32853;
  const value = serializeXorMappedAddress(ip, port);
  assert.equal(value.length, 8);
  assert.equal(value[1], 0x01); // IPv4 family
  const parsed = parseXorMappedAddress(value);
  assert.equal(parsed.family, 0x01);
  assert.equal(parsed.ip, ip);
  assert.equal(parsed.port, port);
});

test('XOR-MAPPED-ADDRESS IPv4 produces correct wire bytes for known vector', () => {
  // RFC 5389 example: 192.0.2.1:32853, cookie 0x2112A442
  // port 32853 = 0x8055; XOR 0x2112 = 0xA147 → bytes A1 47
  // addr XOR cookie = c0000201 XOR 2112A442 = e112a643
  const value = serializeXorMappedAddress('192.0.2.1', 32853);
  assert.deepEqual(Array.from(value), [0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43]);
});

test('XOR-MAPPED-ADDRESS IPv4 with zero-length port value still parses', () => {
  // port 0 is valid
  const value = serializeXorMappedAddress('10.0.0.1', 0);
  const parsed = parseXorMappedAddress(value);
  assert.equal(parsed.port, 0);
  assert.equal(parsed.ip, '10.0.0.1');
});

test('serializeXorMappedAddress rejects invalid IPv4', () => {
  assert.throws(() => serializeXorMappedAddress('999.0.0.1', 80), /IPv4/);
  assert.throws(() => serializeXorMappedAddress('1.2.3', 80), /IPv4/);
});

test('serializeXorMappedAddress rejects invalid port', () => {
  assert.throws(() => serializeXorMappedAddress('1.2.3.4', -1), /port/);
  assert.throws(() => serializeXorMappedAddress('1.2.3.4', 65536), /port/);
});

// --- XOR-MAPPED-ADDRESS IPv6 ---

test('XOR-MAPPED-ADDRESS IPv6 round-trips', () => {
  const ip = '2001:db8::1';
  const port = 50000;
  const txn = Buffer.from([0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c]);
  const value = serializeXorMappedAddress(ip, port, txn);
  assert.equal(value.length, 20);
  assert.equal(value[1], 0x02);
  const parsed = parseXorMappedAddress(value, txn);
  assert.equal(parsed.family, 0x02);
  assert.equal(parsed.ip, '2001:db8::1');
  assert.equal(parsed.port, port);
});

test('XOR-MAPPED-ADDRESS IPv6 requires transactionId', () => {
  const value = Buffer.alloc(20);
  value[1] = 0x02;
  assert.throws(() => parseXorMappedAddress(value), /transactionId/);
});

test('serializeXorMappedAddress IPv6 requires 12-byte transactionId', () => {
  assert.throws(
    () => serializeXorMappedAddress('2001:db8::1', 5, Buffer.alloc(11)),
    /transactionId/,
  );
});

// --- IPv6 parse/format helpers ---

test('formatIPv6 compresses longest zero run per RFC 5952', () => {
  assert.equal(formatIPv6(Buffer.from([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1])), '::1');
  assert.equal(
    formatIPv6(Buffer.from([0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,0x01])),
    '2001:db8::1',
  );
  assert.equal(
    formatIPv6(Buffer.from([0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,0x01])),
    '2001:db8::1',
  );
});

test('formatIPv6 does not compress a single zero group', () => {
  // 2001:db8:0:1:2:3:4:5 → no ::
  const buf = Buffer.from([0x20,0x01,0x0d,0xb8,0,0,0,1,0,2,0,3,0,4,0,5]);
  assert.equal(formatIPv6(buf), '2001:db8:0:1:2:3:4:5');
});

test('parseIPv6 rejects embedded IPv4 form (documented limitation)', () => {
  assert.equal(parseIPv6('::ffff:192.0.2.1'), null);
});

test('parseIPv6 rejects multiple ::', () => {
  assert.equal(parseIPv6('1::2::3'), null);
});

test('parseIPv6 rejects wrong group count', () => {
  assert.equal(parseIPv6('1:2:3:4:5:6:7'), null);
  assert.equal(parseIPv6('1:2:3:4:5:6:7:8:9'), null);
});

test('parseIPv6 parses full and compressed forms', () => {
  const full = parseIPv6('2001:0db8:0000:0000:0000:0000:0000:0001');
  assert.notEqual(full, null);
  assert.equal(full.length, 16);
  assert.equal(full[0], 0x20);
  assert.equal(full[15], 0x01);
  const comp = parseIPv6('2001:db8::1');
  assert.notEqual(comp, null);
  assert.deepEqual(Array.from(comp), Array.from(full));
});

// --- Full TLV wrap of XOR-MAPPED-ADDRESS ---

test('full serializeAttribute + parseXorMappedAddress pipeline for IPv4', () => {
  const value = serializeXorMappedAddress('203.0.113.42', 9876);
  const attr = serializeAttribute(STUN_ATTRIBUTE_TYPE.XOR_MAPPED_ADDRESS, value);
  const parsed = parseAttribute(attr);
  assert.equal(parsed.type, STUN_ATTRIBUTE_TYPE.XOR_MAPPED_ADDRESS);
  const addr = parseXorMappedAddress(parsed.value);
  assert.equal(addr.ip, '203.0.113.42');
  assert.equal(addr.port, 9876);
});

test('MAGIC_COOKIE has the expected value', () => {
  assert.equal(MAGIC_COOKIE, 0x2112a442);
});
