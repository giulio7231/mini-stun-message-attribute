/**
 * Core STUN TLV (attribute) parser and serializer with XOR-MAPPED-ADDRESS support.
 *
 * Zero third-party dependencies. Node standard library only.
 */

/**
 * The STUN magic cookie. Defined in RFC 5389 §3.
 */
export const MAGIC_COOKIE = 0x2112a442;

/**
 * Attribute types we understand. Not an exhaustive list of every IANA-registered
 * attribute — only those this library parses in a special way (XOR-MAPPED-ADDRESS)
 * plus the most common pass-through attributes.
 */
export const STUN_ATTRIBUTE_TYPE = Object.freeze({
  MAPPED_ADDRESS: 0x0001,
  XOR_MAPPED_ADDRESS: 0x0020,
  ERROR_CODE: 0x0009,
});

/**
 * RFC 5389 §15.1: attributes are TLVs on a 4-byte boundary.
 *
 * The 16-bit type is followed by a 16-bit value-length and then the value itself.
 * The value MAY be padded to a 4-byte boundary with trailing bits that MUST be ignored
 * on read and SHOULD be zero on write. We always write zero padding.
 */

/**
 * Parse one TLV attribute starting at *offset* in *buf*.
 *
 * We deliberately do NOT validate that the padding bytes are zero — the RFC only
 * says they MUST be ignored on read, and real-world traffic contains garbage there.
 *
 * @param {Buffer} buf - buffer containing a single STUN attribute (no header before it)
 * @param {number} [offset=0] - where the attribute begins
 * @returns {{type:number,length:number,value:Buffer,raw:Buffer}} the parsed attribute.
 *   *length* is the value-length field (pre-padding); *value* is a zero-copy slice of buf.
 *   *raw* is the entire attribute including padding.
 * @throws {Error} if the attribute is truncated or the length field exceeds the buffer.
 */
export function parseAttribute(buf, offset = 0) {
  if (!Buffer.isBuffer(buf)) {
    throw new TypeError('buf must be a Buffer');
  }
  if (!Number.isInteger(offset) || offset < 0) {
    throw new TypeError('offset must be a non-negative integer');
  }
  if (offset + 4 > buf.length) {
    throw new Error(`attribute header truncated at offset ${offset}`);
  }
  const type = buf.readUInt16BE(offset);
  const length = buf.readUInt16BE(offset + 2);
  const valueStart = offset + 4;
  if (valueStart + length > buf.length) {
    throw new Error(`attribute value truncated: need ${length} bytes, have ${buf.length - valueStart}`);
  }
  const value = buf.subarray(valueStart, valueStart + length);
  // Padded to 4-byte boundary. Length=0 → 0 pad. Length=1,2,3,4 → pad 3,2,1,0 respectively.
  const pad = (4 - (length % 4)) % 4;
  const rawEnd = valueStart + length + pad;
  if (rawEnd > buf.length) {
    // Don't require the padding bytes to actually exist in the buffer — only the value.
    // But if the caller intends to use *raw* downstream, they typically include it.
    // We allow the buffer to end exactly at the value; raw is then the header+value only.
  }
  const raw = buf.subarray(offset, Math.min(rawEnd, buf.length));
  return { type, length, value, raw };
}

/**
 * Serialize a single attribute to a Buffer, with zero padding to a 4-byte boundary.
 *
 * @param {number} type - attribute type (16-bit)
 * @param {Buffer} value - attribute value (raw bytes)
 * @returns {Buffer} the serialized attribute including type, length, and padding.
 * @throws {Error} if type is out of range or value is not a Buffer.
 */
export function serializeAttribute(type, value) {
  if (!Number.isInteger(type) || type < 0 || type > 0xffff) {
    throw new Error('type must be an integer in [0, 0xffff]');
  }
  if (!Buffer.isBuffer(value)) {
    throw new TypeError('value must be a Buffer');
  }
  const pad = (4 - (value.length % 4)) % 4;
  const out = Buffer.alloc(4 + value.length + pad);
  out.writeUInt16BE(type, 0);
  out.writeUInt16BE(value.length, 2);
  value.copy(out, 4);
  // padding bytes are already zero from alloc
  return out;
}

/**
 * XOR a 4-byte IPv4 address with the magic cookie.
 *
 * XOR-MAPPED-ADDRESS in IPv4 mode XORs only the 32-bit address with the 32-bit cookie.
 * IPv6 mode XORs the 128-bit address with (cookie || transaction_id), which means we
 * need the transaction ID from the STUN header to parse IPv6. This is the awkward edge —
 * see parseXorMappedAddress below.
 */

/**
 * Serialize an XOR-MAPPED-ADDRESS attribute value (without the outer TLV header).
 *
 * Layout (RFC 5389 §15.2):
 *   byte 0: reserved (top 7 bits) + family (bottom 1 bit's neighbour, actually: 00 00 0FAM)
 *   Actually per RFC: byte 0 = 0x00 (reserved), byte 1 = family (0x01=IPv4, 0x02=IPv6)
 *   bytes 2-3: XOR'd port (port XOR high 16 bits of cookie)
 *   bytes 4-7: XOR'd IPv4 (addr XOR cookie)
 *   bytes 4-19: XOR'd IPv6 (addr XOR cookie || transaction_id)
 *
 * @param {string} ip - dotted IPv4 or colon-separated IPv6
 * @param {number} port - 16-bit port
 * @param {Buffer} [transactionId] - 12-byte transaction ID, REQUIRED for IPv6
 * @returns {Buffer} the attribute *value* (no TLV header). Caller wraps with serializeAttribute.
 * @throws {Error} on invalid IP, port, or missing transactionId for IPv6.
 */
export function serializeXorMappedAddress(ip, port, transactionId) {
  if (!Number.isInteger(port) || port < 0 || port > 0xffff) {
    throw new Error('port must be an integer in [0, 65535]');
  }
  if (ip.includes(':') && !ip.includes('.')) {
    // IPv6
    if (!Buffer.isBuffer(transactionId) || transactionId.length !== 12) {
      throw new Error('IPv6 requires a 12-byte transactionId Buffer');
    }
    const addr = parseIPv6(ip);
    if (addr === null) {
      throw new Error(`invalid IPv6 address: ${ip}`);
    }
    // mask: magic cookie (4 bytes) || transaction ID (12 bytes) = 16 bytes
    const mask = Buffer.alloc(16);
    mask.writeUInt32BE(MAGIC_COOKIE, 0);
    transactionId.copy(mask, 4);
    const xored = Buffer.alloc(16);
    for (let i = 0; i < 16; i++) {
      xored[i] = addr[i] ^ mask[i];
    }
    const out = Buffer.alloc(20);
    out[0] = 0x00; // reserved
    out[1] = 0x02; // family IPv6
    out.writeUInt16BE(port ^ (MAGIC_COOKIE >>> 16), 2);
    xored.copy(out, 4);
    return out;
  } else {
    // IPv4
    const parts = ip.split('.');
    if (parts.length !== 4 || !parts.every((p) => { const n = Number(p); return Number.isInteger(n) && n >= 0 && n <= 255; })) {
      throw new Error(`invalid IPv4 address: ${ip}`);
    }
    const addr = Buffer.from(parts.map((p) => Number(p)));
    const xored = Buffer.alloc(4);
    for (let i = 0; i < 4; i++) {
      xored[i] = addr[i] ^ ((MAGIC_COOKIE >>> (8 * (3 - i))) & 0xff);
    }
    const out = Buffer.alloc(8);
    out[0] = 0x00; // reserved
    out[1] = 0x01; // family IPv4
    out.writeUInt16BE(port ^ (MAGIC_COOKIE >>> 16), 2);
    xored.copy(out, 4);
    return out;
  }
}

/**
 * Parse an XOR-MAPPED-ADDRESS attribute value back into {family, ip, port}.
 *
 * For IPv6, the transaction ID from the STUN message header is required to undo the XOR.
 * We accept it as a Buffer here rather than trying to extract it from a full message —
 * the caller knows it, and keeping this function focused on one attribute avoids coupling
 * to the overall message structure.
 *
 * @param {Buffer} value - the attribute *value* (what parseAttribute returns as .value)
 * @param {Buffer} [transactionId] - 12-byte transaction ID, required for IPv6
 * @returns {{family:number, ip:string, port:number}}
 * @throws {Error} on truncation, bad family, or missing transactionId for IPv6.
 */
export function parseXorMappedAddress(value, transactionId) {
  if (!Buffer.isBuffer(value)) {
    throw new TypeError('value must be a Buffer');
  }
  if (value.length < 4) {
    throw new Error(`XOR-MAPPED-ADDRESS value too short: ${value.length} bytes`);
  }
  if (value[0] !== 0x00) {
    // Reserved top bits MUST be zero on read per RFC, but some implementations send nonzero.
    // We warn-tolerate by masking rather than throwing — this is a deliberate choice.
  }
  const family = value[1];
  const xport = value.readUInt16BE(2);
  const port = xport ^ (MAGIC_COOKIE >>> 16);
  if (family === 0x01) {
    if (value.length < 8) {
      throw new Error(`IPv4 XOR-MAPPED-ADDRESS truncated: need 8, have ${value.length}`);
    }
    const addr = Buffer.alloc(4);
    for (let i = 0; i < 4; i++) {
      addr[i] = value[4 + i] ^ ((MAGIC_COOKIE >>> (8 * (3 - i))) & 0xff);
    }
    return { family, ip: `${addr[0]}.${addr[1]}.${addr[2]}.${addr[3]}`, port };
  } else if (family === 0x02) {
    if (!Buffer.isBuffer(transactionId) || transactionId.length !== 12) {
      throw new Error('IPv6 XOR-MAPPED-ADDRESS requires a 12-byte transactionId Buffer');
    }
    if (value.length < 20) {
      throw new Error(`IPv6 XOR-MAPPED-ADDRESS truncated: need 20, have ${value.length}`);
    }
    const mask = Buffer.alloc(16);
    mask.writeUInt32BE(MAGIC_COOKIE, 0);
    transactionId.copy(mask, 4);
    const addr = Buffer.alloc(16);
    for (let i = 0; i < 16; i++) {
      addr[i] = value[4 + i] ^ mask[i];
    }
    return { family, ip: formatIPv6(addr), port };
  } else {
    throw new Error(`unknown address family: ${family}`);
  }
}

/**
 * Minimal IPv6 text parser into 16 bytes.
 *
 * Handles full 8-group notation and :: compression. Does NOT support embedded IPv4
 * (e.g. ::ffff:1.2.3.4) — we made the call that pure IPv6 text is enough for STUN
 * mapped-address work, and the embedded-v4 form adds a class of edge cases that the
 * rest of the library doesn't need. Documented as a limitation.
 */
export function parseIPv6(text) {
  if (typeof text !== 'string' || text.length === 0) return null;
  // Reject embedded IPv4 form explicitly — see JSDoc above.
  if (text.includes('.')) return null;
  // Disallow multiple :: — exactly one is allowed.
  const doubleColons = (text.match(/::/g) || []).length;
  if (doubleColons > 1) return null;
  const out = new Uint8Array(16);
  let groups;
  let gapIndex = -1;
  if (doubleColons === 1) {
    const [head, tail] = text.split('::');
    const headGroups = head.length === 0 ? [] : head.split(':');
    const tailGroups = tail.length === 0 ? [] : tail.split(':');
    const total = headGroups.length + tailGroups.length;
    if (total > 7) return null;
    gapIndex = headGroups.length;
    groups = headGroups.concat(tailGroups);
    const zeroCount = 8 - total;
    // We'll fill the gap with zero groups during placement.
    let gi = 0;
    let oi = 0;
    for (let i = 0; i < headGroups.length; i++) {
      const g = parseHexGroup(headGroups[i]);
      if (g === null) return null;
      out[oi] = (g >>> 8) & 0xff;
      out[oi + 1] = g & 0xff;
      oi += 2;
    }
    oi += zeroCount * 2; // gap of zeros
    for (let i = 0; i < tailGroups.length; i++) {
      const g = parseHexGroup(tailGroups[i]);
      if (g === null) return null;
      out[oi] = (g >>> 8) & 0xff;
      out[oi + 1] = g & 0xff;
      oi += 2;
    }
    return Buffer.from(out);
  } else {
    groups = text.split(':');
    if (groups.length !== 8) return null;
    for (let i = 0; i < 8; i++) {
      const g = parseHexGroup(groups[i]);
      if (g === null) return null;
      out[i * 2] = (g >>> 8) & 0xff;
      out[i * 2 + 1] = g & 0xff;
    }
    return Buffer.from(out);
  }
}

/**
 * Parse one 16-bit hex group. Empty string is invalid (only valid inside :: gap).
 * Returns the integer or null.
 */
function parseHexGroup(s) {
  if (s.length === 0 || s.length > 4) return null;
  if (!/^[0-9a-fA-F]+$/.test(s)) return null;
  return parseInt(s, 16);
}

/**
 * Format 16 raw bytes as canonical lowercase IPv6 text with :: compression.
 *
 * Implements the RFC 5952 canonical form: longest run of zero groups compressed,
 * ties broken by earliest, and no compression of a single zero group.
 */
export function formatIPv6(buf) {
  const groups = [];
  for (let i = 0; i < 8; i++) {
    groups.push((buf[i * 2] << 8 | buf[i * 2 + 1]) >>> 0);
  }
  // Find longest run of consecutive zeros, length >= 2.
  let bestStart = -1;
  let bestLen = 1;
  let curStart = -1;
  let curLen = 0;
  for (let i = 0; i < 8; i++) {
    if (groups[i] === 0) {
      if (curStart === -1) curStart = i;
      curLen++;
      if (curLen > bestLen) {
        bestLen = curLen;
        bestStart = curStart;
      }
    } else {
      curStart = -1;
      curLen = 0;
    }
  }
  // Only compress runs of length >= 2 per RFC 5952.
  if (bestLen < 2) {
    return groups.map((g) => g.toString(16)).join(':');
  }
  const before = groups.slice(0, bestStart).map((g) => g.toString(16));
  const after = groups.slice(bestStart + bestLen).map((g) => g.toString(16));
  let result = before.join(':');
  result += '::';
  result += after.join(':');
  return result;
}
