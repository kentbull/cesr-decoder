const encoder = new TextEncoder();
const decoder = new TextDecoder();

/**
 * A class for encoding a string to a bytearray or a bytearray to a string in the UTF-8 encoding.
 */
export class Utf8 {
    /**
     * Encode a string to a Uint8Array bytearray using the built-in TextEncoder.
     * @param value {string}
     * @returns {Uint8Array}
     */
    static encode(value) {
        return encoder.encode(value);
    }

    /**
     * Decode a Uint8Array bytearray to a string using the built-in TextDecoder.
     * @param value {Uint8Array}
     * @returns {string}
     */
    static decode(value) {
        return decoder.decode(value);
    }
}
