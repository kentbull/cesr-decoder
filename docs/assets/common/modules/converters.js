/**
 * Functions for converting between bytearray, number, and string representations of data.
 * @module converters
 */

/**
 * Converts an array of bytes into a number using big-endian bit shifting.
 *
 * Borrowed from SignifyTS.
 *
 * @param array {Uint8Array}
 * @returns {number}
 */
export function readInt(array) {
  let value = 0;
  for (let i = 0; i < array.length; i++) {
    value = value * 256 + array[i];
  }
  return value;
}
