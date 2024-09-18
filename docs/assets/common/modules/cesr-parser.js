import {
    CesrVersionHeader,
    // eslint-disable-next-line no-unused-vars
    CesrCodeTable,
    // eslint-disable-next-line no-unused-vars
    CesrProtocol,
    Serials,
    UnknownCodeError,
    ShortageError,
    UnexpectedCountCodeError,
    UnexpectedCodeError,
    UnexpectedOpCodeError,
    ConversionError,
} from "./cesr.js";
import { Hex } from "../../local/modules/hex.js";
import { Utf8 } from "../../local/modules/utf8.js";
import { CountCodeStart, CounterHards, MatterHards, OpCodeStart } from "./cesr-tables.js";
import { Base64 } from "../../local/modules/base64.js";

import { readInt } from "./converters.js";

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
    constructor({ header, value }) {
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
    if (total !== value.length) throw new UnknownCodeError(`getCesrValue ${protocol.name}`, JSON.stringify(code));

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
};

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
    switch (
        tritet // binary AND 11100000 to isolate first three bytes
    ) {
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
 *
 * @param cesrValue {CesrValue}
 * @param protocol {CesrProtocol}
 * @param input {Uint8Array}
 * @param derivationCode {CesrDerivationCode}
 * @returns {CesrValue}
 */
function getSealSourceTriples(cesrValue, protocol, input, derivationCode) {
    // TODO needs to know if parsing QB64 or QB2 since counts will be different.
    // strip off the count code
    const table = protocol.getCodeTable(cesrValue.header.selector);
    const fs = table.getTotalLength(cesrValue.header);
    const triple = input.slice(fs);
    let tripleSize = 0;

    const [_counterHard, count] = fromCounterQB64b(input.slice(0, fs), protocol);

    for (let i = 0; i < count; i++) {
        const [_prefix_hard, prefix_size, _prefix_raw] = parsePrefixQB64(protocol, triple);
        const seqnerStartPosition = prefix_size;
        const [_seqner_hard, seqner_size, _seqner_raw] = parseSeqnerQB64(protocol, triple.slice(seqnerStartPosition));
        const saiderStartPosition = seqnerStartPosition + seqner_size;
        const [_saider_hard, saider_size, _saider_raw] = parseSaider(protocol, triple.slice(saiderStartPosition));
        tripleSize += prefix_size + seqner_size + saider_size;
    }

    derivationCode.leadBytes = 0;
    derivationCode.size = fs;
    derivationCode.count = count;
    derivationCode.index = -1;
    derivationCode.ondex = -1;
    return new CesrValue({
        header: derivationCode,
        value: input.slice(0, fs + tripleSize),
    });
}

/**
 * Extracts identifier prefix from qualified Base64URLSafe string or bytes.
 * Detects if string and converts to bytes.
 * @param protocol {CesrProtocol}
 * @param input {string | Uint8Array}
 * @returns {CesrValue}
 */
function parsePrefixQB64(protocol, input) {
    return fromMatterQB64b(input, protocol);
}

/**
 * Parses a sequence number from qualified Base64URLSafe string or bytes.
 * Detects if string and converts to bytes.
 * @param protocol {CesrProtocol}
 * @param input {string | Uint8Array}
 * @returns {CesrValue}
 */
function parseSeqnerQB64(protocol, input) {
    return fromMatterQB64b(input, protocol);
}

/**
 * Parses a self addressing identifier (SAID) from qualified Base64URLSafe string or bytes.
 * Detects if string and converts to bytes.
 * @param protocol {CesrProtocol}
 * @param input {string | Uint8Array}
 * @returns {CesrValue}
 */
function parseSaider(protocol, input) {
    return fromMatterQB64b(input, protocol);
}

/**
 * Extracts non-count code, non-indexed primitive including the derivation code and raw byte value from a qualified
 * Base64URLSafe cryptographic primitive that is string or bytes.
 *
 * Similar to Matter._exfil in KERIpy.
 * @param qb64b {string | Uint8Array}
 * @param protocol {CesrProtocol}
 * @returns {[string, number, Uint8Array]}
 */
function fromMatterQB64b(qb64b, protocol) {
    if (!(qb64b instanceof Uint8Array)) {
        if (typeof qb64b === "string") {
            qb64b = Utf8.encode(qb64b);
        } else {
            throw new TypeError("fromMatterQB64b: Expected Uint8Array or string, got " + typeof qb64b);
        }
    }
    if (!qb64b || !qb64b.length || qb64b.length === 0) throw new ShortageError("fromMatterQB64b: Empty material");
    let first = qb64b.slice(0, 1); // get first character code selector
    first = Utf8.decode(first);
    if (!(first in MatterHards)) {
        if (first[0] === CountCodeStart) throw new UnexpectedCountCodeError("Unexpected count code start while extracting Matter.");
        else if (first[0] === OpCodeStart) throw new UnexpectedOpCodeError("Unexpected op code start while extracting Matter.");
        else throw new UnexpectedCodeError(`Unknown code '${first[0]}' start while extracting Matter.`);
    }
    let hardSize = MatterHards[first];
    if (qb64b.length < hardSize) throw new ShortageError(`fromMatterQB64b: Need ${hardSize - qb64b.length} more characters.`);

    const hardBytes = qb64b.slice(0, hardSize);
    const hard = Utf8.decode(hardBytes);
    const table = protocol.getCodeTable(hard);
    let { hs, ss, fs, ls } = table.spec.sizes;

    let cs = hs + ss; // code size is hard size + soft size
    let size = 0;
    if (fs === null || fs === undefined) {
        if (cs % 4 !== 0) throw new Error("fromMatterQB64b: Code size not divisible by 4");
        const sizeBytes = qb64b.slice(hs, cs); // extract size chars
        const sizeChars = Utf8.decode(sizeBytes);
        size = Base64.toInt(sizeChars); // compute int size
        fs = size * 4 + cs;
    }

    // assumes unit tests on Matter and MatterCodex ensure codes and sizes are well-formed, as in
    // hs is consistent, ss === 0 and not fs % 4 and hs > 0 and fs >= hs + ss unless fs is None

    if (qb64b.length < fs) throw new ShortageError(`fromMatterQB64b: Need ${fs - qb64b.length} more characters.`);

    qb64b = qb64b.slice(0, fs);

    let raw = new Uint8Array(0); // raw bytes of cryptographic primitive

    // check for non-zeroed pad bits or lead bytes
    const ps = cs % 4; // code pad size ps = cs mod 4
    const pbs = 2 * (ps ? ps : ls); // Pad bit size in bits
    if (ps > 0) {
        const padding = new Uint8Array(ps).fill(65); // pad with 'A' characters
        const base = new Uint8Array([...padding, ...qb64b.slice(cs)]);
        // paw = padded raw bytes
        const paw = Base64.decodeBase64Url(base); // Decode base to leave pre-padded raw, then make bytes again
        // pi = pad integer
        const pi = readInt(paw.slice(0, ps)); // read the integer value of the pad bits
        if (pi & (2 ** pbs - 1)) throw new Error(`fromMatterQB64b: Non-zeroed pad bits = ${(pi & (2 ** pbs - 1)).toString(16)} in ${qb64b.slice(cs, cs + 1)}`);
        raw = paw.slice(ps); //strip off ps pre-pad paw bytes
    } else {
        // Not ps. If not ps then may or may not be ls (lead bytes)
        const base = qb64b.slice(cs); // strip off code leaving lead chars, if any, and value
        // decode lead chars + value leaving lead bytes + raw bytes
        // then strip off ls lead bytes leaving raw
        const paw = Base64.decodeBase64Url(base);
        const li = readInt(paw.slice(0, ls)); // read the integer value of the lead bytes
        if (li > 0) {
            if (ls === 1) throw new Error(`fromMatterQB64b: Non-zeroed lead byte = ${li.toString(16)} in ${qb64b.slice(cs, cs + 1)}`);
            else throw new Error(`fromMatterQB64b: Non-zeroed lead bytes = ${li.toString(16)} in ${qb64b.slice(cs, cs + ls)}`);
        }
        raw = paw.slice(ls); // strip off ls lead bytes
    }
    if (raw.length !== Math.floor(((qb64b.length - cs) * 3) / 4) - ls) {
        throw new ConversionError(`Improperly qualified material: ${Utf8.encode(qb64b)}`);
    }
    return [hard, fs, raw];
}

/**
 * Create a fully qualified Base64 representation of the raw bytes encoded as bytes.
 * This implementation only uses the hard part of the code as SAIDs do not have a variable part (soft size).
 *
 * Analogous to Matter._infil() function from KERIpy. Most comments here are taken from that function.
 *
 * @param raw {Uint8Array} - the raw bytes to encode
 * @param code {string} the derivation code selector to use to look up sizes
 * @param protocol {CesrProtocol} the CESR protocol specifying the code table
 * @returns {Uint8Array} - UTF8 encoded bytes of the fully qualified Base64 representation of the raw bytes
 */
export function toMatterQB64b(raw, code, protocol) {
    const table = protocol.getCodeTable(code);
    let { hs, ss, ls } = table.spec.sizes;
    const cs = hs + ss;
    const rs = raw.length;
    const ps = (3 - ((rs + ls) % 3)) % 3; // net pad size given raw size and lead size
    // net pad size must equal both code size remainder so that primitive both + converted padded raw is fs long.
    // Assumes ls in (0, 1, 2) and cs % 4 != 3, fs % 4 == 0. Sizes table must ensure these properties.
    // Even still, following check is a good idea.
    if (cs % 4 !== ps - ls) {
        throw new Error(`Invalid code size and raw pad size ${ps} given raw length ${rs}`);
    }

    // Prepad raw so we midpad the full primitive. Prepadding with ps+ls zero bytes ensures encodeB64 of
    // prepad+lead+raw has no trailing pad characters. Finally skip first ps == cs % 4 of the converted characters
    // to ensure that when full code is prepended the full primitive size is fs but midpad bits are zeros.
    const prepad = new Uint8Array(ps + ls);
    const paddedRaw = new Uint8Array(prepad.length + raw.length);

    // fill out prepad
    // when fixed and ls != 0 then cs % 4 is zero and ps === ls
    // otherwise fixed and ls === 0 then cs % 4 === ps
    for (let i = 0; i < ps; i++) {
        prepad[i] = 0;
    }
    paddedRaw.set(prepad);
    // adjust the bytes considering padding
    paddedRaw.set(raw, prepad.length);
    const b64Padded = Base64.encodeBase64Url(paddedRaw);
    const unpaddedB64 = b64Padded.substring(cs % 4);

    return Utf8.encode(code + unpaddedB64);
}

/**
 * Extracts count code primitive including the derivation code and raw byte value from a qualified
 * Base64URLSafe cryptographic primitive that is string or bytes.
 *
 * Similar to Counter._exfil in KERIpy.
 * @param qb64b {string | Uint8Array}
 * @param protocol {CesrProtocol}
 * @returns {[string, number, Uint8Array]}
 */
function fromCounterQB64b(qb64b, protocol) {
    if (!(qb64b instanceof Uint8Array)) {
        if (typeof qb64b === "string") {
            qb64b = Utf8.encode(qb64b);
        } else {
            throw new TypeError("fromCounterQB64b: Expected Uint8Array or string, got " + typeof qb64b);
        }
    }
    if (!qb64b || !qb64b.length || qb64b.length === 0) throw new ShortageError("fromMatterQB64b: Empty material");
    let first = qb64b.slice(0, 2); // count codes are two characters since they include '-'
    first = Utf8.decode(first);
    if (!(first in CounterHards)) {
        if (first[0] === OpCodeStart) throw new UnexpectedOpCodeError("Unexpected op code start while extracting Counter.");
        else throw new UnexpectedCodeError(`Unknown code '${first[0]}' start while extracting Counter.`);
    }
    let hardSize = CounterHards[first];
    if (qb64b.length < hardSize) throw new ShortageError(`fromCounterQB64b: Need ${hardSize - qb64b.length} more characters.`);

    const hardBytes = qb64b.slice(0, hardSize);
    const hard = Utf8.decode(hardBytes);
    const table = protocol.getCodeTable(hard);
    let { hs, fs } = table.spec.sizes;

    if (qb64b.length < fs) throw new ShortageError(`fromCounterQB64b: Need ${fs - qb64b.length} more characters.`);

    let countCodeB64 = qb64b.slice(hs, fs);
    let countInt = Base64.toInt(Utf8.decode(countCodeB64));
    return [hard, countInt];
}

// function toCounterQB64b(raw, code, protocol) {}

/**
 * Parse the correct count of quadlets (set of 4 Base64 characters) from tine input byte array.
 * @param input {Uint8Array} CESR stream byte array
 * @param derivationCode {CesrDerivationCode]
 * @param quadletCount {number}
 * @param codeLength {number}
 * @returns {CesrValue}
 */
function getAttachedMaterialQuadlets(input, derivationCode, quadletCount, codeLength) {
    const size = quadletCount * 4 + codeLength;
    if (size > input.length) throw new UnknownCodeError(`getAttachedMaterialQuadlets not enough data for`, JSON.stringify(derivationCode));

    return new CesrValue({
        header: derivationCode,
        value: input.slice(0, size),
    });
}

/**
 * @param {CesrProtocol} protocol
 * @param {Uint8Array} input
 * @return {CesrValue}
 */
function getTextFrame(protocol, input) {
    // assumes the count code is left at the front of the input so it can be returned in the CesrValue
    const cesrValue = getCesrValue(protocol, input);
    switch (cesrValue.header.selector) {
        case "-I": // Seal source triples
            // extract count code from stream
            return getSealSourceTriples(cesrValue, protocol, input, cesrValue.header);
        case "-V": // Attached material quadlets
            // TODO check whether input has selector stripped prior to processing
            return getAttachedMaterialQuadlets(input, cesrValue.header, cesrValue.header.count, cesrValue.header.length);
        case "-0V": // Big attached material quadlets
            return getAttachedMaterialQuadlets(input, cesrValue.header, cesrValue.header.count, cesrValue.header.length);
        default:
            throw new UnknownCodeError(`getTextFrame`, JSON.stringify(cesrValue.header));
    }
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
        value: input.slice(0, code.size),
    });
}
