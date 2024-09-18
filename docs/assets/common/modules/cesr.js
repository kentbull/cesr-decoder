/*

https://weboftrust.github.io/ietf-cesr/draft-ssmith-cesr.html
https://weboftrust.github.io/ietf-cesr-proof/draft-pfeairheller-cesr-proof.html
https://trustoverip.github.io/tswg-acdc-specification/draft-ssmith-acdc.html

https://www.typescriptlang.org/docs/handbook/jsdoc-supported-types.html

*/

export class ConversionError extends Error {
    constructor(message) {
        super(message);
    }
}

export class UnknownCodeError extends Error {
    /** @type {string} */
    code;
    /**
     * @param {string} message
     * @param {string} code
     */
    constructor(message, code) {
        super(`${message} code=${code}`);
        this.code = code;
    }
}

export class UnexpectedCountCodeError extends Error {
    /** @type {string} */
    code;
    constructor(message, code) {
        super(`${message} code=${code}`);
        this.code = code;
    }
}

export class UnexpectedOpCodeError extends Error {
    /** @type {string} */
    code;
    constructor(message, code) {
        super(`${message} code=${code}`);
        this.code = code;
    }
}

export class UnexpectedCodeError extends Error {
    /** @type {string} */
    code;
    constructor(message, code) {
        super(`${message} code=${code}`);
        this.code = code;
    }
}

export class ShortageError extends Error {
    /** @type {number} */
    length;
    /** @type {number} */
    expected;
    constructor(message, length, expected) {
        super(`${message} length=${length} expected=${expected}`);
        this.length = length;
        this.expected = expected;
    }
}

export const Serials = Object.freeze({
    json: 'JSON',
    mgpk: 'MGPK',
    cbor: 'CBOR'
})

/**
 * The version string of a CESR primitive encoded in JSON, CBOR, MGPK, etc.
 * https://weboftrust.github.io/ietf-cesr/draft-ssmith-cesr.html#section-3.16
 */
export class CesrVersionHeader {
    /**
     * @type {CesrCodeTable}
     */
    table;
    /**
     * The complete CESR Version string
     * @type {string}
     */
    value;
    /**
     * The serialization type JSON, CBOR, MGPK, etc.
     * @type {string}
     */
    serial;
    /**
     * The protocol type whether KERI, ACDC, etc.
     * @type {string}
     */
    proto;
    /**
     * Length of code header. Same as {@link CesrCodeTable.codeSize}
     * @type {number}
     */
    get length() { return this.value.length; }

    /**
     * Creates a CesrCodeHeader representing the version string header of a CESR cryptographic primitive.
     * @param {object} obj
     */
    constructor(obj) {
        this.table = obj.table;
        this.value = obj.value;
        this.serial = obj.serial;
        this.proto = obj.proto;
        // define optional property digits
        if (Object.hasOwn(obj, "digits")) this.digits = obj.digits;
        // define optional context specific properties
        for (const key of ["typeName", "leadBytes", "size", "count", "quadlets", "version", "index", "ondex"]) {
            if (Object.hasOwn(obj, key) && obj[key] !== undefined) {
                const descriptor = {
                    enumerable: true
                };
                if (typeof obj[key] === "function") {
                    descriptor["get"] = obj[key];
                } else {
                    descriptor["value"] = obj[key];
                }
                Object.defineProperty(this, key, descriptor);
            }
        }
    }
}

/**
 * The derivation code of an encoded CESR primitive.
 * https://weboftrust.github.io/ietf-cesr/draft-ssmith-cesr.html#section-3.16
 */
export class CesrDerivationCode {
    /**
     * @type {CesrCodeTable}
     */
    table;
    /**
     * The complete CESR Version string
     * @type {string}
     */
    value;
    /**
     * The text selector of a CESR derivation code.
     * @type {string}
     */
    selector;
    /**
     * The type of derivation code whether group code, index code, matter code, or otherwise.
     * @type {string}
     */
    type;

    /**
     * Size of the primitive encoded as Base64URLSafe characters.
     * @type {string | undefined}
     */
    digits;

    /**
     * The characters of the derivation code indicating its type.
     * @type {string}
     */
    typeName;

    /**
     * Quantity of lead pad bytes
     * @type {number | undefined}
     */
    leadBytes;

    /**
     * The integer representation of the Base64 digits field.
     * @type {number | undefined}
     */
    size;

    /**
     * Count of quadlets in the CESR primitive.
     * @type {number | undefined}
     */
    count;
    /**
     * Count of quadlets in the CESR primitive.
     * @type {number | undefined}
     */
    quadlets;
    /**
     * Version number string of the CESR primitive.
     * Remove if not needed.
     * @type {string | undefined}
     */
    version;
    /**
     * The index of an indexed CESR primitive.
     * @type {number | undefined}
     */
    index;
    /**
     * The other index of an indexed CESR primitive.
     * @type {number | undefined}
     */
    ondex;

    /**
     * Length of code header. Same as {@link CesrCodeTable.codeSize}
     * @type {number}
     */
    get length() { return this.value.length; }

    /**
     * Creates a CesrCodeHeader representing the version string header of a CESR cryptographic primitive.
     * @param {object} obj
     */
    constructor({table, value, selector, type, digits, typeName, leadBytes, size, count, quadlets, version, index, ondex}) {
        this.table = table;
        this.value = value;
        this.selector = selector;
        this.type = type;
        this.typeName = typeName;
        this.digits = digits; // define optional property digits
        this.leadBytes = leadBytes;
        this.size = size;
        this.count = count;
        this.quadlets = quadlets;
        this.version = version;
        this.index = index;
        this.ondex = ondex;
        // define optional context specific properties
        for (const key of ["typeName", "leadBytes", "size", "count", "quadlets", "version", "index", "ondex"]) {
            if (Object.hasOwn(this, key) && this[key] !== undefined) {
                const descriptor = {
                    enumerable: true
                };
                if (typeof this[key] === "function") {
                    descriptor["get"] = this[key];
                } else {
                    descriptor["value"] = this[key];
                }
                Object.defineProperty(this, key, descriptor);
            }
        }
    }
}

/**
 * Map selector string of 1 or 2 chars to code table {@link CesrCodeTable}
 * Abstract class
 * Implementation {@link CesrSchemaProtocol}
 */
export class CesrProtocol {
    /** @type {string} */
    get name() { return this.constructor.name; }
    /**
     * @param {string} selector
     * @returns {number}
     */
    getSelectorSize(_selector) {
        return 1;
    }
    /**
     * @param {string} selector
     * @returns {CesrCodeTable}
     */
    getCodeTable(selector) {
        throw new UnknownCodeError(`${this.name}.getCodeTable`, selector);
    }
    /**
     * @param {CesrVersionHeader} _code
     * @returns {string}
     */
    getTypeName(_code) {
        return undefined;
    }
    /**
     * @param {CesrVersionHeader} _code
     * @returns {boolean}
     */
    isFrame(_code) {
        return false;
    }
    /**
     * @param {CesrVersionHeader} _code
     * @returns {boolean}
     */
    isGroup(_code) {
        return false;
    }
    /**
     * @param {CesrVersionHeader} _code
     * @returns {boolean}
     */
    hasContext(_code) {
        return false;
    }
    /**
     * @param {CesrVersionHeader} _code
     * @returns {CesrProtocol}
     */
    getContext(_code) {
        return undefined;
    }
    /**
     * @returns {string}
     */
    toJSON() { return this.name; }
}

/**
 * Split selector string into selector specific code header parts
 * Abstract class
 * Implementation {@link CesrSchemaCodeTable}
 */
export class CesrCodeTable {
    #protocol;
    /**
     * @param {CesrProtocol} protocol
     */
    constructor(protocol) {
        if (!(protocol instanceof CesrProtocol)) throw new TypeError();
        this.#protocol = protocol;
    }
    /** @type {string} */
    get name() { return this.constructor.name; }
    /** @type {number} */
    get codeSize() { throw new UnknownCodeError(`${this.name}.codeSize`); }
    /**
     * @param {string} code
     * @returns {CesrDerivationCode}
     */
    mapCodeHeader(code) {
        code = code.slice(0, this.codeSize);
        throw new UnknownCodeError(`${this.name}.mapCodeHeader`, code);
    }
    /**
     * @param {CesrVersionHeader} code
     * @returns {number}
     */
    getTotalLength(code) {
        throw new UnknownCodeError(`${this.name}.getTotalLength`, code.value);
    }
    /**
     * @param {CesrVersionHeader} code
     * @returns {number}
     */
    getGroupCount(code) {
        throw new UnknownCodeError(`${this.name}.getGroupCount`, code.value);
    }
    /**
     * @param {CesrVersionHeader} code
     * @returns {number}
     */
    getLeadBytes(code) {
        throw new UnknownCodeError(`${this.name}.getLeadBytes`, code.value);
    }
    /**
     * Implements CesrCodeHeader.typeName
     * @returns {funtion}
     */
    get _typeNameGetter() {
        const self = this;
        /**
         * @this {CesrVersionHeader}
         */
        return function () {
            return self.#protocol.getTypeName(this);
        }
    }
    /**
     * Implements CesrCodeHeader.count
     * @returns {funtion}
     */
    get _countGetter() {
        const self = this;
        /**
         * @this {CesrVersionHeader}
         */
        return function () {
            return self.getGroupCount(this);
        }
    }
    /**
     * Implements CesrCodeHeader.leadBytes
     * @returns {funtion}
     */
    get _leadBytesGetter() {
        const self = this;
        /**
         * @this {CesrVersionHeader}
         */
        return function () {
            return self.getLeadBytes(this);
        }
    }
    /** @returns {string} */
    toJSON() { return this.name; }
}

export { CesrValue, getCesrValue, getCesrFrame } from "./cesr-parser.js";
