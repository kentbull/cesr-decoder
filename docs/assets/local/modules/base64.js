export class Base64 {
    static #BASE64
        = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        + "abcdefghijklmnopqrstuvwxyz"
        + "0123456789"
        + "-_";
    /**
     * @param {string} value
     * @returns {number}
     */
    static valueOf(ch) {
        // TODO: reverse map instead of indexOf
        const r = Base64.#BASE64.indexOf(ch);
        if (r == -1) throw new Error();
        return r;
    }
    /**
     * @param {string} value
     * @returns {number}
     */
    static toInt1(value) {
        return Base64.toInt(value.slice(0, 1));
    }
    /**
     * @param {string} value
     * @returns {number}
     */
    static toInt2(value) {
        return Base64.toInt(value.slice(0, 2));
    }
    /**
     * @param {string} value
     * @returns {number}
     */
    static toInt3(value) {
        return Base64.toInt(value.slice(0, 3));
    }
    /**
     * @param {string} value
     * @returns {number}
     */
    static toInt4(value) {
        return Base64.toInt(value.slice(0, 4));
    }
    /**
     * @param {string} value
     * @returns {number}
     */
    static toInt(value) {
        let result = 0;
        for (const ch of value) {
            result <<= 6;
            result |= Base64.valueOf(ch);
        }
        return result;
    }

    /**
     * Decodes Base64URLSafe bytes to a Uint8Array
     * @param array {Uint8Array} - input bytes to decode
     * @returns {Uint8Array} - decoded bytes
     */
    static decodeBase64Url(array) {
        if (!(array instanceof Uint8Array)) {
            throw new TypeError('`array`` must be a Uint8Array.');
        }
        let base64UrlString = '';
        for (let i = 0; i < array.length; i++) {
            base64UrlString += String.fromCharCode(array[i]);
        }
        const base64String = base64UrlString
          .replace(/-/g, '+')  // ASCII 45 to 43
          .replace(/_/g, '/'); // ASCII 95 to 47

        // Base64 aligns on 24 bit boundaries, or 4 Base64 chars, using padding.
        const modRemainder = base64String.length % 4;
        const padCharCount = modRemainder > 0 ? 4 - modRemainder : 0
        const paddedB64Str = base64String + '='.repeat(padCharCount); // is ASCII 61

        // All Base64 characters are ASCII characters so we can use atob (ASCII to binary).
        const binaryString = atob(paddedB64Str);

        // Convert the binary string to a Uint8Array
        const outputArray = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            outputArray[i] = binaryString.charCodeAt(i);
        }
        return outputArray
    }

    /**
     * Encodes a Uint8Array to Base64URLSafe string.
     * @param array {Uint8Array} - input bytes to encode
     * @param strip {boolean} - strip Base64 padding '=' characters
     * @returns {string} - Base64URLSafe encoded string
     */
    static encodeBase64Url(array, strip = true) {
        if (!(array instanceof Uint8Array)) {
            throw new TypeError('`array`` must be a Uint8Array.');
        }
        // Convert Uint8Array to binary string
        let binaryString = '';
        for (let i = 0; i < array.length; i++) {
            binaryString += String.fromCharCode(array[i]);
        }
        // Encode binary string to base64.
        // Base64 and Base64URLSafe use only ASCII characters so we can use btoa (binary to ASCII)
        let base64String = btoa(binaryString);
        // Replace URL-unsafe characters and remove padding
        const base64UrlString = base64String
          .replace(/\+/g, '-')
          .replace(/\//g, '_');
        if(strip) {
            return base64UrlString
              .replace(/=+$/, ''); // Remove any trailing '=' characters
        } else {
            return base64UrlString;
        }
    }
}

