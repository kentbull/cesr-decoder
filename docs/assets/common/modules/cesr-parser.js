import {CesrVersionHeader, CesrCodeTable, CesrProtocol, Serials, UnknownCodeError} from "./cesr.js";
import {Hex} from "../../local/modules/hex.js";
import {Utf8} from "../../local/modules/utf8.js";

/**
 * An encoded CESR value along with its looked up derivation code
 */
export class CesrValue {
  /** @type {CesrCodeTable} */
  get table() {
    return this.header.table;
  }

  /** @type {CesrDerivationCode | CesrVersionHeader} */
  header;
  /** @type {Uint8Array} */
  value;

  /** @type {number} */
  get length() {
    return this.value.length;
  }

  /** @param {{header, value}} obj */
  constructor({header, value}) {
    this.header = header;
    this.value = value;
  }
}

/**
 * Get first CESR T code from input
 * @param {CesrProtocol} protocol
 * @param {string | Uint8Array} input
 * @returns {CesrValue}
 */
export function getCesrValue(protocol, input) {
  let selector;
  if ("string" === typeof input) {
    selector = input.slice(0, 8);
    input = Utf8.encode(input);
  } else if (input instanceof Uint8Array) {
    const tmp = input.slice(0, 8);
    selector = Utf8.decode(tmp);
  } else {
    throw new TypeError(`expected input "string" or "Uint8Array"`);
  }

  // length of selector
  const selectorSize = protocol.getSelectorSize(selector);
  if (selectorSize > selector.length) throw new UnknownCodeError(`getCesrValue ${protocol.name}`, selector);

  // lookup code table with selector
  const table = protocol.getCodeTable(selector.slice(0, selectorSize));
  if (table.codeSize > selector.length) throw new UnknownCodeError(`getCesrValue ${protocol.name}`, selector);

  // map to cesr code header
  const code = table.mapCodeHeader(selector.slice(0, table.codeSize));

  // get total length of cesr code
  const total = table.getTotalLength(code);
  if (total > input.length) throw new UnknownCodeError(`getCesrValue ${protocol.name}`, JSON.stringify(code));

  // read cesr code
  const value = input.slice(0, total);
  if (total != value.length) throw new UnknownCodeError(`getCesrValue ${protocol.name}`, JSON.stringify(code));

  return new CesrValue({
    header: code,
    value: value,
  });
}

/**
 * Cold start stream tritet codex.
 *
 * List of types (codex) of cold stream start tritets - the first three bits of the first byte of the stream.
 * The values are in octal notation.
 *
 * Reference: ToIP CESR spec section 10.5.1 "Performant resynchronization with unique start bits"
 * https://trustoverip.github.io/tswg-cesr-specification/#performant-resynchronization-with-unique-start-bits
 *
 * @type {{Free: number, CtB64: number, OpB64: number, JSON: number, MGPK1: number, CBOR: number, MGPK2: number, CtOpB2: number}}
 */
let ColdDex = {
  /**
   * Not taken, yet planned for annotated CESR
   * Binary 000, full binary value 00000000
   */
  Free: 0o0,
  /**
   * CountCode Base64URLSafe starting character ('-') tritet, position 62 or 0x3E.
   * Tritet bits 001, full binary 00101101, hex 0x2D
   * Tritet is first three bits of the '-' character, ASCII/UTF-8 45.
   */
  CtB64: 0o1,
  /**
   * OpCode Base64URLSafe starting character ('_'), position 63 or 0x3F.
   * Tritet bits 010, full binary 01011111, hex 0x5F
   * Tritet is first three bits of the '_' character, ASCII/UTF-8 character 95.
   */
  OpB64: 0o2,
  /**
   * JSON Map starting character ('{') tritet.
   * Tritet bits 011, full binary value 01111011, hex 0x7B
   * Tritet is first three bits of the '{' character, ASCII/UTF-8 character 123.
   */
  JSON: 0o3,
  /**
   * MessagePack Fixed Map Event Start tritet
   * Binary 100, full binary ?
   */
  MGPK1: 0o4,
  /**
   * CBOR Map Event Start
   * Binary 101, full binary ?
   */
  CBOR: 0o5,
  /**
   * MessagePack Big 16 or 32 Map Event Start
   * Binary 110, full binary ?
   */
  MGPK2: 0o6,
  /**
   * Base2 (binary) CountCode or OpCode starting character tritet
   * Binary 111, full binary ?
   */
  CtOpB2: 0o7,
}

/**
 * Get next CESR frame from input. Performs the "Parser.sniff" operation from KERIpy.
 * CESR T group, CESR T op, JSON, MGPK, CBOR, CESR B
 * @param {CesrProtocol} protocol
 * @param {string | Uint8Array} input
 * @returns {CesrValue}
 */
export function getCesrFrame(protocol, input) {
  if ("string" === typeof input) {
    input = Utf8.encode(input);
  } else if (input instanceof Uint8Array) {
    // nothing
  } else {
    throw new TypeError(`expected input "string" or "Uint8Array"`);
  }

  // https://weboftrust.github.io/ietf-cesr/draft-ssmith-cesr.html#section-3.6.1
  const tritet = input[0] >> 5; // get the first three bits to determine frame type
  switch (tritet) { // binary AND 11100000 to isolate first three bytes
    // Corresponds to binary 00100000 - Like ColdDex.CtB64
    case ColdDex.CtB64: // '-' Base64 CountCode start character
      return getTextFrame(protocol, input);
    // Corresponds to binary 01100000 - Like ColdDex.JSON
    case ColdDex.JSON: // '{' JSON Map start character
      return getJsonFrame(input);
    // TODO: op, binary, cbor, mgpk
    default:
      throw new UnknownCodeError(`getCesrFrame`, input[0]);
  }
}

/**
 * @param {CesrProtocol} protocol
 * @param {Uint8Array} input
 * @return {CesrValue}
 */
function getTextFrame(protocol, input) {
  const value = getCesrValue(protocol, input);
  switch (value.header.selector) {
    case "-V":
      break;
    case "-0V":
      break;
    default:
      throw new UnknownCodeError(`getTextFrame`, JSON.stringify(value.header));
  }

  const size = value.header.count * 4 + value.header.length;
  if (size > input.length) throw new UnknownCodeError(`getTextFrame`, JSON.stringify(value.header));

  return new CesrValue({
    header: value.header,
    value: input.slice(0, size)
  });
}

/**
 * @param {Uint8Array} input
 * @return {CesrValue}
 */
function getJsonFrame(input) {
  // {"v":"KERI10JSON0000fc_"
  const versionStrHeader = Utf8.decode(input.slice(0, 24));
  const versionStrPattern = /^{"\w{1}":"(\w{16})_"/;
  const versionStrMatch = versionStrPattern.exec(versionStrHeader);
  if (versionStrMatch === null) throw new UnknownCodeError(`getJsonFrame`, versionStrHeader);

  const versionStr = versionStrMatch[1];
  const code = new CesrVersionHeader({
    table: undefined,
    value: versionStr,
    serial: versionStr.slice(6, 10), // JSON
    proto: versionStr.slice(0, 6), // KERI10
    digits: versionStr.slice(10, 16), // 0000fc,
    size: function () {
      return Hex.toInt(this.digits);
    },
  });

  if (Serials.json !== code.serial) throw new UnknownCodeError(`getJsonFrame`, JSON.stringify(code));

  if (code.size > input.length) new UnknownCodeError(`getJsonFrame`, JSON.stringify(code));

  return new CesrValue({
    header: code,
    value: input.slice(0, code.size)
  });
}
