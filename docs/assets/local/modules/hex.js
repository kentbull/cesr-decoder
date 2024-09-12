export class Hex {
    static #HEX = "0123456789ABCDEF";
    /**
     * @param {string} value
     * @returns {number}
     */
    static valueOf(ch) {
        // TODO: reverse map instead of indexOf
        const r = Hex.#HEX.indexOf(ch);
        if (r == -1) throw new Error();
        return r;
    }
    /**
     * @param {string} value
     * @returns {number}
     */
    static toInt(value) {
        let result = 0;
        for (const ch of value.toUpperCase()) {
            result <<= 4;
            result |= Hex.valueOf(ch);
        }
        return result;
    }

    /**
     * Encodes a Uint8Array to a hexadecimal string
     * @param {Uint8Array} uint8Array
     * @returns {string}
     */
    static encode(uint8Array) {
        return Array.from(uint8Array, byte => byte.toString(16).padStart(2, '0')).join('');
    }

    /**
     * Decodes a hexadecimal string to a Uint8Array
     * @param hexString {string} - input string to decode
     * @returns {Uint8Array}
     */
    static decode(hexString) {
        if (hexString.length % 2 !== 0) {
            throw new Error("Invalid hex string");
        }

        const uint8Array = new Uint8Array(hexString.length / 2);

        for (let i = 0; i < hexString.length; i += 2) {
            uint8Array[i / 2] = parseInt(hexString.substring(i, 2), 16);
        }

        return uint8Array;
    }
}
