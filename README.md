# mini-stun-message-attribute

Parses and serializes STUN (RFC 5389) attribute type-length-value pairs, including XOR-MAPPED-ADDRESS for NAT traversal, in pure JavaScript with no dependencies.

## Usage

```js
import {
  serializeAttribute,
  parseAttribute,
  serializeXorMappedAddress,
  parseXorMappedAddress,
  STUN_ATTRIBUTE_TYPE,
} from 'mini-stun-message-attribute';

// Build an XOR-MAPPED-ADDRESS attribute for 192.0.2.1:32853 (IPv4)
const value = serializeXorMappedAddress('192.0.2.1', 32853);
const attr = serializeAttribute(STUN_ATTRIBUTE_TYPE.XOR_MAPPED_ADDRESS, value);
// attr is a Buffer: [00 20] [00 08] [00 01 A1 46 E1 12 A6 43]

const parsed = parseAttribute(attr);
// parsed.type === 0x0020, parsed.length === 8, parsed.value is the 8-byte value
const addr = parseXorMappedAddress(parsed.value);
// addr.ip === '192.0.2.1', addr.port === 32853

// IPv6 needs the 12-byte transaction ID from the STUN message header
const txnId = Buffer.from('0102030405060708090a0b0c', 'hex');
const v6Value = serializeXorMappedAddress('2001:db8::1', 50000, txnId);
const v6Addr = parseXorMappedAddress(v6Value, txnId);
// v6Addr.ip === '2001:db8::1', v6Addr.port === 50000
```

## Exports

- `parseAttribute(buf, offset=0)` → `{ type, length, value, raw }`
- `serializeAttribute(type, value)` → `Buffer` (zero-padded to 4-byte boundary)
- `parseXorMappedAddress(value, transactionId?)` → `{ family, ip, port }`
- `serializeXorMappedAddress(ip, port, transactionId?)` → `Buffer` (attribute *value*, no TLV header)
- `parseIPv6(text)` → `Buffer` of 16 bytes or `null`
- `formatIPv6(buf)` → canonical RFC 5952 text
- `STUN_ATTRIBUTE_TYPE` — frozen map of known type codes
- `MAGIC_COOKIE` — `0x2112a442`

## Why this exists

XOR-MAPPED-ADDRESS is the attribute a STUN server puts in a response to tell a client its reflexive (public) transport address — the thing a NAT assigned to it. Getting it right matters because the value is XORed with the STUN magic cookie (and, for IPv6, the transaction ID) so that NAT boxes that rewrite IP addresses in the packet body don't silently corrupt the attribute.

The trade-off here is scope: this library handles attribute TLV framing and the XOR-MAPPED-ADDRESS family specifically. It does not parse the 20-byte STUN message header, validate message integrity, or manage transactions. If you need a full STUN client, wrap this — but most uses of the attribute (testing, debugging, embedding in a larger protocol) want exactly this slice and no more.

## Awkward edges

- **IPv6 needs the transaction ID.** IPv4 XOR-MAPPED-ADDRESS only depends on the fixed magic cookie, so it can be parsed in isolation. IPv6 XORs the address with `cookie || transactionId`, which means you cannot parse an IPv6 attribute value without the 12-byte transaction ID from the STUN message header. The API takes it as an explicit argument rather than coupling to a full-message parser.
- **Padding is ignored on read, zeroed on write.** Per RFC 5389, attribute values are padded to a 4-byte boundary and the padding bits MUST be ignored on read. Real traffic has nonzero garbage in those bytes; `parseAttribute` does not validate them. `serializeAttribute` always writes zeros.
- **Embedded-IPv4 IPv6 text is not supported.** `parseIPv6` rejects forms like `::ffff:192.0.2.1`. This keeps the IPv6 text parser small and focused; if you need that form, expand `parseIPv6` before using it with `serializeXorMappedAddress`.

## Tests

`node --test` from the project root. All tests are deterministic and use no wall-clock time.
