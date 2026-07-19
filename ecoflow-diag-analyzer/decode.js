// EcoFlow diagnostics decode pipeline - JS port of ha-ef-ble eflib primitives.
// Covers: CRC8/CRC16, AES-CBC (WebCrypto, padding-agnostic), scan record,
// frame assemblers (encrypt_type 0/1/7), Packet V2/V3/V19/V4 parsing.
'use strict';

// ---------------------------------------------------------------------------
// CRC (same polynomials as eflib/crc.py)
// ---------------------------------------------------------------------------

const CRC8_TABLE = new Uint8Array(256);
for (let i = 0; i < 256; i++) {
  let c = i;
  for (let j = 0; j < 8; j++) c = (c & 0x80) ? ((c << 1) ^ 0x07) & 0xFF : (c << 1) & 0xFF;
  CRC8_TABLE[i] = c;
}
function crc8(data) {
  let c = 0;
  for (const b of data) c = CRC8_TABLE[c ^ b];
  return c;
}

const CRC16_TABLE = new Uint16Array(256);
for (let i = 0; i < 256; i++) {
  let c = i;
  for (let j = 0; j < 8; j++) c = (c & 1) ? (c >>> 1) ^ 0xA001 : c >>> 1;
  CRC16_TABLE[i] = c;
}
function crc16(data) {
  let c = 0;
  for (const b of data) c = ((c >>> 8) ^ CRC16_TABLE[(c ^ b) & 0xFF]) & 0xFFFF;
  return c;
}

// ---------------------------------------------------------------------------
// Byte helpers
// ---------------------------------------------------------------------------

function hexToBytes(hex) {
  if (!hex) return new Uint8Array(0);
  const out = new Uint8Array(hex.length >> 1);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}
function bytesToHex(arr) {
  return Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
}
function concatBytes(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0); out.set(b, a.length);
  return out;
}
function readU16LE(d, off) { return d[off] | (d[off + 1] << 8); }
function indexOfSeq(data, seq, start = 0) {
  outer: for (let i = start; i <= data.length - seq.length; i++) {
    for (let j = 0; j < seq.length; j++) if (data[i + j] !== seq[j]) continue outer;
    return i;
  }
  return -1;
}

// ---------------------------------------------------------------------------
// AES-CBC decrypt without padding enforcement.
// WebCrypto insists on PKCS7; append one block that decrypts to valid padding
// (encrypt 16x 0x10 with IV = last ciphertext block), then drop it.
// ---------------------------------------------------------------------------

async function importAesKey(keyBytes) {
  return crypto.subtle.importKey('raw', keyBytes, { name: 'AES-CBC' }, false,
    ['encrypt', 'decrypt']);
}

async function aesCbcDecryptRaw(key, iv, ciphertext) {
  const aligned = ciphertext.length - (ciphertext.length % 16);
  if (aligned === 0) return ciphertext;
  const ct = ciphertext.subarray(0, aligned);
  const lastBlock = ct.subarray(aligned - 16, aligned);
  const padBlock = new Uint8Array(16).fill(0x10);
  // encrypt() appends its own padding block; take only the first 16 bytes
  const sentinel = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-CBC', iv: lastBlock }, key, padBlock)
  ).subarray(0, 16);
  const plain = new Uint8Array(
    await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, key, concatBytes(ct, sentinel))
  );
  return plain; // sentinel block already stripped as "padding" by WebCrypto
}

function pkcs7Unpad(data) {
  if (data.length === 0 || data.length % 16 !== 0) return data;
  const n = data[data.length - 1];
  if (n < 1 || n > 16 || n > data.length) return data;
  for (let i = data.length - n; i < data.length; i++) if (data[i] !== n) return data;
  return data.subarray(0, data.length - n);
}

// Type7: PKCS7 (tolerating bad padding); Type1: null padding kept as-is
class Type7Encryption {
  constructor(key, iv) { this.key = key; this.iv = iv; }
  async decrypt(ciphertext) {
    const plain = await aesCbcDecryptRaw(this.key, this.iv, ciphertext);
    return pkcs7Unpad(plain);
  }
}
class Type1Encryption {
  constructor(key, iv) { this.key = key; this.iv = iv; }
  async decrypt(ciphertext) {
    return aesCbcDecryptRaw(this.key, this.iv, ciphertext);
  }
}

// ---------------------------------------------------------------------------
// Scan record (eflib devicebase._ScanRecordV2)
// ---------------------------------------------------------------------------

function parseScanRecord(mfgData) {
  const capability = mfgData.length > 19 ? mfgData[22] : 0b0111000;
  return {
    protoVersion: mfgData[0],
    serialNumber: new TextDecoder().decode(mfgData.subarray(1, 17)),
    status: mfgData.length > 17 ? mfgData[17] : 0,
    productType: mfgData.length > 18 ? mfgData[18] : 0,
    encrypt: (capability & 0b0000001) !== 0,
    encryptType: (capability & 0b0111000) >> 3,
  };
}

// ---------------------------------------------------------------------------
// Packet parsing (eflib packet.py)
// ---------------------------------------------------------------------------

const PACKET_PREFIX = 0xAA;
const ENCPACKET_PREFIX = new Uint8Array([0x5A, 0x5A]);

function parsePacket(data, xorPayload) {
  if (data.length === 0 || data[0] !== PACKET_PREFIX) {
    return { error: 'prefix incorrect', raw: data };
  }
  const versionByte = data[1];
  if (versionByte === 4) return parsePacketV4(data);

  const version = versionByte & 0x0F;
  const sentinelFormat = (versionByte & 0x10) !== 0;

  if ((version === 2 && data.length < 18) || (version === 3 && data.length < 20)) {
    return { error: 'too small', raw: data };
  }
  const payloadLength = readU16LE(data, 2);

  const endsBB = data.length >= 2 &&
    data[data.length - 1] === 0xBB && data[data.length - 2] === 0xBB;
  if ((version === 2 || version === 3) && !sentinelFormat && !endsBB) {
    if (crc16(data.subarray(0, data.length - 2)) !== readU16LE(data, data.length - 2)) {
      return { error: 'incorrect CRC16', raw: data };
    }
  }
  if (crc8(data.subarray(0, 4)) !== data[4]) {
    return { error: 'incorrect header CRC8', raw: data };
  }

  const seq = data.subarray(6, 10);
  const src = data[12];
  const dst = data[13];
  let dsrc = 0, ddst = 0, cmdSet, cmdId;
  const payloadStart = version === 2 ? 16 : 18;
  if (version === 2) {
    cmdSet = data[14]; cmdId = data[15];
  } else {
    dsrc = data[14]; ddst = data[15]; cmdSet = data[16]; cmdId = data[17];
  }

  let payload = new Uint8Array(0);
  if (payloadLength > 0) {
    payload = data.slice(payloadStart, payloadStart + payloadLength);
    if (xorPayload && seq[0] !== 0) {
      for (let i = 0; i < payload.length; i++) payload[i] ^= seq[0];
    }
    if (sentinelFormat && payload.length >= 2 &&
        payload[payload.length - 1] === 0xBB && payload[payload.length - 2] === 0xBB) {
      payload = payload.subarray(0, payload.length - 2);
    }
  }

  return {
    src, dst, cmdSet, cmdId, payload, dsrc, ddst,
    version: versionByte, seq: Array.from(seq), raw: data,
  };
}

function parsePacketV4(data) {
  if (data.length < 18) return { error: 'too small', raw: data };
  const payloadLength = readU16LE(data, 2);
  if (data.length !== 8 + payloadLength + 2) return { error: 'V4 length mismatch', raw: data };
  if (crc16(data.subarray(0, data.length - 2)) !== readU16LE(data, data.length - 2)) {
    return { error: 'incorrect CRC16', raw: data };
  }
  if (crc8(data.subarray(0, 4)) !== data[4]) {
    return { error: 'incorrect header CRC8', raw: data };
  }
  if (payloadLength < 8) return { error: 'V4 payload too short', raw: data };

  const v4TypeB = data[7];
  const xorKey = data[4];
  const inner = new Uint8Array(payloadLength);
  for (let i = 0; i < payloadLength; i++) inner[i] = data[8 + i] ^ xorKey;

  let payload = inner.slice(8);
  if (v4TypeB) for (let i = 0; i < payload.length; i++) payload[i] ^= v4TypeB;

  return {
    src: inner[4], dst: inner[5], cmdSet: inner[6], cmdId: inner[7],
    payload, dsrc: 0, ddst: 0, version: 4, seq: [inner[3], 0, 0, 0], raw: data,
  };
}

// ---------------------------------------------------------------------------
// Frame assemblers (eflib frame_assembler.py) - stateful, feed notifications in order
// ---------------------------------------------------------------------------

class PassthroughAssembler {
  constructor() { this.buffer = new Uint8Array(0); }
  async reassemble(data) {
    data = concatBytes(this.buffer, data);
    this.buffer = new Uint8Array(0);
    const payloads = [];
    while (data.length) {
      const start = data.indexOf(PACKET_PREFIX);
      if (start < 0) { data = new Uint8Array(0); break; }
      if (start > 0) data = data.subarray(start);
      if (data.length < 5) break;
      if (crc8(data.subarray(0, 4)) !== data[4]) { data = data.subarray(1); continue; }
      const payloadLength = readU16LE(data, 2);
      const versionByte = data[1];
      let frameLen;
      if (versionByte === 4) frameLen = 8 + payloadLength + 2;
      else {
        const innerOverhead = (versionByte & 0x0F) >= 3 ? 15 : 13;
        frameLen = 5 + innerOverhead + payloadLength;
      }
      if (data.length < frameLen) break;
      payloads.push(data.slice(0, frameLen));
      data = data.subarray(frameLen);
    }
    this.buffer = data.slice();
    return payloads;
  }
}

class RawHeaderAssembler {
  constructor(encryption) { this.enc = encryption; this.buffer = new Uint8Array(0); }
  async reassemble(data) {
    data = concatBytes(this.buffer, data);
    this.buffer = new Uint8Array(0);
    const payloads = [];
    while (data.length) {
      const start = data.indexOf(PACKET_PREFIX);
      if (start < 0) { data = new Uint8Array(0); break; }
      if (start > 0) data = data.subarray(start);
      if (data.length < 5) break;
      if (crc8(data.subarray(0, 4)) !== data[4]) { data = data.subarray(1); continue; }
      const payloadLength = readU16LE(data, 2);
      const version = data[1];
      let innerOverhead;
      if (version === 4) innerOverhead = 5;
      else if (version >= 3) innerOverhead = 15;
      else innerOverhead = 13;
      const innerLen = innerOverhead + payloadLength;
      const encryptedLen = Math.ceil(innerLen / 16) * 16;
      const frameLen = 5 + encryptedLen;
      if (data.length < frameLen) break;
      const header = data.slice(0, 5);
      const encryptedBody = data.subarray(5, frameLen);
      data = data.subarray(frameLen);
      const decrypted = await this.enc.decrypt(encryptedBody);
      payloads.push(concatBytes(header, decrypted.subarray(0, innerLen)));
    }
    this.buffer = data.slice();
    return payloads;
  }
}

class EncPacketAssembler {
  constructor(encryption) { this.enc = encryption; this.buffer = new Uint8Array(0); }
  async reassemble(data) {
    data = concatBytes(this.buffer, data);
    this.buffer = new Uint8Array(0);
    const payloads = [];
    while (data.length) {
      const start = indexOfSeq(data, ENCPACKET_PREFIX);
      if (start < 0) { data = new Uint8Array(0); break; }
      if (start > 0) data = data.subarray(start);
      if (data.length < 8) break;
      const payloadLen = readU16LE(data, 4);
      if (payloadLen > 10000) { data = data.subarray(2); continue; }
      const dataEnd = 6 + payloadLen;
      if (dataEnd > data.length) {
        const next = indexOfSeq(data, ENCPACKET_PREFIX, 2);
        if (next >= 0) { data = data.subarray(next); continue; }
        break;
      }
      const headerAndPayload = data.subarray(0, dataEnd - 2);
      const payloadCrc = readU16LE(data, dataEnd - 2);
      if (crc16(headerAndPayload) !== payloadCrc) { data = data.subarray(2); continue; }
      const payloadData = data.slice(6, dataEnd - 2);
      data = data.subarray(dataEnd);
      payloads.push(await this.enc.decrypt(payloadData));
    }
    this.buffer = data.slice();
    return payloads;
  }
}

// ---------------------------------------------------------------------------
// Dump loader - parses a diagnostics JSON and decodes all packets
// ---------------------------------------------------------------------------

function looksEncrypted(dump) {
  const data = dump.data ?? dump;
  return typeof data.session === 'string' && data.session.length > 0;
}

async function decodeDump(dump, { xorPayload = true } = {}) {
  const data = dump.data ?? dump;
  if (looksEncrypted(dump)) {
    throw new Error(
      'This dump is encrypted with the developer public key. In the ' +
      'integration options disable "Encrypt diagnostics data" (and keep ' +
      '"Enable packet collection" on), then download the diagnostics again.'
    );
  }

  const mfg = hexToBytes(data.manufacturer_data ?? '');
  const scan = mfg.length >= 17 ? parseScanRecord(mfg) : null;

  const info = {
    device: data.device ?? null,
    name: data.name ?? null,
    snPrefix: data.sn_prefix ?? (scan ? scan.serialNumber.slice(0, 4) : null),
    connectionState: data.connection_state ?? null,
    encryptType: scan ? scan.encryptType : null,
    timestamp: dump.timestamp ?? null,
    exception: dump.exception ?? null,
  };

  const sessionKey = hexToBytes(data.session_key ?? '');
  const iv = hexToBytes(data.iv ?? '');

  let assembler = null;
  const encType = scan ? scan.encryptType : (sessionKey.length ? 7 : 0);
  if (encType === 0) {
    assembler = new PassthroughAssembler();
  } else if (sessionKey.length === 16 && iv.length === 16) {
    const key = await importAesKey(sessionKey);
    assembler = encType === 1
      ? new RawHeaderAssembler(new Type1Encryption(key, iv))
      : new EncPacketAssembler(new Type7Encryption(key, iv));
  }

  const packets = [];
  const errors = [];

  const rawStreams = [
    ...(data.raw_data_connection ?? []),
    ...(data.raw_data_messages ?? []),
  ];
  if (assembler && rawStreams.length) {
    for (const [time, hex] of rawStreams) {
      let frames;
      try {
        frames = await assembler.reassemble(hexToBytes(hex));
      } catch (e) {
        errors.push({ time, error: String(e) });
        continue;
      }
      for (const frame of frames) {
        const pkt = parsePacket(frame, xorPayload);
        if (pkt.error) errors.push({ time, error: pkt.error, raw: frame });
        else packets.push({ time, ...pkt });
      }
    }
  }

  // last_packets are already-decrypted packet bytes - use as fallback / extra
  // source when raw streams produced nothing (e.g. diagnostics buffer variants)
  if (!packets.length && Array.isArray(data.last_packets)) {
    for (const [time, hex] of data.last_packets) {
      const pkt = parsePacket(hexToBytes(hex), xorPayload);
      if (pkt.error) errors.push({ time, error: pkt.error });
      else packets.push({ time, ...pkt });
    }
  }

  return { info, packets, errors };
}

// ---------------------------------------------------------------------------
// Schema-less protobuf wire walker
// Produces flat map of fieldPath -> interpretations, recursing into plausible
// sub-messages. Paths look like "1", "3.2", "3.2[1]" for repeated occurrences.
// ---------------------------------------------------------------------------

function readVarint(d, pos) {
  let result = 0n, shift = 0n, p = pos;
  while (p < d.length) {
    const b = d[p++];
    result |= BigInt(b & 0x7F) << shift;
    if ((b & 0x80) === 0) return [result, p];
    shift += 7n;
    if (shift > 63n) break;
  }
  return null;
}

function zigzagDecode(n) { return (n >> 1n) ^ -(n & 1n); }

function bigToNum(n) {
  const num = Number(n);
  return Number.isSafeInteger(num) ? num : n.toString();
}

function tryParseMessage(d) {
  // Returns list of {fieldNo, wireType, value...} or null if not a valid message
  const fields = [];
  let pos = 0;
  while (pos < d.length) {
    const v = readVarint(d, pos);
    if (!v) return null;
    const [tag, p1] = v;
    pos = p1;
    const fieldNo = Number(tag >> 3n);
    const wireType = Number(tag & 7n);
    if (fieldNo === 0 || fieldNo > 536870911) return null;
    switch (wireType) {
      case 0: {
        const val = readVarint(d, pos);
        if (!val) return null;
        fields.push({ fieldNo, wireType, varint: val[0] });
        pos = val[1];
        break;
      }
      case 1: {
        if (pos + 8 > d.length) return null;
        fields.push({ fieldNo, wireType, bytes: d.slice(pos, pos + 8) });
        pos += 8;
        break;
      }
      case 2: {
        const len = readVarint(d, pos);
        if (!len) return null;
        const l = Number(len[0]);
        if (len[1] + l > d.length) return null;
        fields.push({ fieldNo, wireType, bytes: d.slice(len[1], len[1] + l) });
        pos = len[1] + l;
        break;
      }
      case 5: {
        if (pos + 4 > d.length) return null;
        fields.push({ fieldNo, wireType, bytes: d.slice(pos, pos + 4) });
        pos += 4;
        break;
      }
      default:
        return null;
    }
  }
  return fields.length ? fields : null;
}

function isProbablyText(bytes) {
  if (!bytes.length) return false;
  for (const b of bytes) {
    if (b < 0x20 && b !== 0x09 && b !== 0x0A && b !== 0x0D) return false;
    if (b > 0x7E) return false;
  }
  return true;
}

function interpretField(f) {
  // Multi-interpretation of one wire field
  const out = { wireType: f.wireType };
  if (f.wireType === 0) {
    out.uint = bigToNum(f.varint);
    const s = zigzagDecode(f.varint);
    out.sint = bigToNum(s);
    // Show int64-as-negative interpretation when high bit set
    if (f.varint > 0x7FFFFFFFFFFFFFFFn) {
      out.int = bigToNum(BigInt.asIntN(64, f.varint));
    }
  } else if (f.wireType === 5) {
    const dv = new DataView(f.bytes.buffer, f.bytes.byteOffset, 4);
    out.uint = dv.getUint32(0, true);
    out.int = dv.getInt32(0, true);
    out.float = dv.getFloat32(0, true);
  } else if (f.wireType === 1) {
    const dv = new DataView(f.bytes.buffer, f.bytes.byteOffset, 8);
    out.uint = bigToNum(dv.getBigUint64(0, true));
    out.int = bigToNum(dv.getBigInt64(0, true));
    out.double = dv.getFloat64(0, true);
  } else if (f.wireType === 2) {
    out.bytes = f.bytes;
    out.hex = bytesToHex(f.bytes);
    if (isProbablyText(f.bytes)) out.text = new TextDecoder().decode(f.bytes);
  }
  return out;
}

function walkMessage(data, prefix = '', depth = 0, out = new Map()) {
  const fields = tryParseMessage(data);
  if (!fields) return null;
  const counts = new Map();
  for (const f of fields) {
    const idx = counts.get(f.fieldNo) ?? 0;
    counts.set(f.fieldNo, idx + 1);
    const base = prefix ? `${prefix}.${f.fieldNo}` : String(f.fieldNo);
    const path = idx === 0 ? base : `${base}[${idx}]`;
    const interp = interpretField(f);
    if (f.wireType === 2 && depth < 6 && f.bytes.length > 1) {
      const sub = walkMessage(f.bytes, path, depth + 1, new Map());
      if (sub) {
        interp.isMessage = true;
        for (const [k, v] of sub) out.set(k, v);
      }
    }
    out.set(path, interp);
  }
  return out;
}

// ---------------------------------------------------------------------------
// V2 fixed-width struct decode (eflib model/base.py semantics: little-endian,
// partial decode by dropping trailing fields that don't fit)
// ---------------------------------------------------------------------------

const STRUCT_SIZES = { b: 1, B: 1, h: 2, H: 2, i: 4, I: 4, q: 8, Q: 8, f: 4, d: 8 };

function structFieldSize(fmt) {
  const m = /^(\d*)s$/.exec(fmt);
  if (m) return m[1] ? parseInt(m[1], 10) : 1;
  return STRUCT_SIZES[fmt] ?? null;
}

function decodeStructField(dv, data, off, fmt) {
  const m = /^(\d*)s$/.exec(fmt);
  if (m) {
    const n = m[1] ? parseInt(m[1], 10) : 1;
    return bytesToHex(data.subarray(off, off + n));
  }
  switch (fmt) {
    case 'b': return dv.getInt8(off);
    case 'B': return dv.getUint8(off);
    case 'h': return dv.getInt16(off, true);
    case 'H': return dv.getUint16(off, true);
    case 'i': return dv.getInt32(off, true);
    case 'I': return dv.getUint32(off, true);
    case 'q': return bigToNum(dv.getBigInt64(off, true));
    case 'Q': return bigToNum(dv.getBigUint64(off, true));
    case 'f': return dv.getFloat32(off, true);
    case 'd': return dv.getFloat64(off, true);
    default: return null;
  }
}

function decodeStruct(data, fields) {
  // fields: [{name, fmt}] -> {values: {name: value|null}, offsets: {name: [off, size]}}
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const values = {};
  const offsets = {};
  let off = 0;
  for (const f of fields) {
    const size = structFieldSize(f.fmt);
    if (size === null) { values[f.name] = null; continue; }
    if (off + size > data.length) {
      values[f.name] = null;
      offsets[f.name] = [off, size];
      off += size;
      continue;
    }
    values[f.name] = decodeStructField(dv, data, off, f.fmt);
    offsets[f.name] = [off, size];
    off += size;
  }
  return { values, offsets, consumed: off };
}

export {
  crc8, crc16, hexToBytes, bytesToHex, concatBytes,
  parseScanRecord, parsePacket, decodeDump, looksEncrypted,
  walkMessage, tryParseMessage, decodeStruct, structFieldSize,
  PassthroughAssembler, RawHeaderAssembler, EncPacketAssembler,
  Type1Encryption, Type7Encryption, importAesKey,
};
