/**
 * @module Conversions
 * This module provides a collection of utility functions for converting
 * between different numerical formats, particularly focusing on
 * conversions involving bigints, hexadecimals and buffers.
 * The module is structured with clear function naming to indicate
 * the conversion direction (e.g., `bigIntToHexadecimal` for BigInt
 * to hexadecimal, `bufferToBigInt` for buffer to bigint) and employs
 * type checks to ensure the correct handling of various input types.
 * It also includes variations for both big-endian (`be`) and little-endian
 * (`le`) conversions. It is important to note that when there is no prefix,
 * the order of bytes is always big-endian.
 */

import { Buffer } from "buffer"
import { requireBigInt, requireBigNumberish, requireHexadecimal, requireString, requireTypes } from "./error-handlers"
import { isBuffer, isHexadecimal, isUint8Array } from "./type-checks"
import { BigNumber, BigNumberish } from "./types"

/**
 * Converts a bigint to a hexadecimal string.
 * @param value The bigint value to convert.
 * @returns The hexadecimal representation of the bigint.
 */
export function bigIntToHexadecimal(value: bigint): string {
    requireBigInt(value, "value")

    let hex = value.toString(16)

    // Ensure even length.
    if (hex.length % 2 !== 0) {
        hex = `0${hex}`
    }

    return hex
}

/**
 * Converts a hexadecimal string to a bigint. The input is interpreted as hexadecimal
 * with or without a '0x' prefix. It uses big-endian byte order.
 * @param value The hexadecimal string to convert.
 * @returns The bigint representation of the hexadecimal string.
 */
export function hexadecimalToBigInt(value: string): bigint {
    if (!isHexadecimal(value) && !isHexadecimal(value, false)) {
        throw new TypeError(`Parameter 'value' is not a hexadecimal string`)
    }

    // Ensure the hex string starts with '0x'.
    const formattedHexString = value.startsWith("0x") ? value : `0x${value}`

    return BigInt(formattedHexString)
}

/**
 * Converts a buffer of bytes to a bigint using big-endian byte order.
 * It accepts 'Buffer' or 'Uint8Array'.
 * @param value The buffer to convert.
 * @returns The bigint representation of the buffer's contents.
 */
export function beBufferToBigInt(value: Buffer | Uint8Array): bigint {
    requireTypes(value, "value", ["Buffer", "Uint8Array"])

    return BigInt(`0x${Buffer.from(value).toString("hex")}`)
}

/**
 * Converts a buffer to a bigint using little-endian byte order.
 * It accepts 'Buffer' or 'Uint8Array'.
 * @param value The buffer to convert.
 * @returns The bigint representation of the buffer's contents in little-endian.
 */
export function leBufferToBigInt(value: Buffer | Uint8Array): bigint {
    requireTypes(value, "value", ["Buffer", "Uint8Array"])

    return BigInt(`0x${Buffer.from(value).reverse().toString("hex")}`)
}

/**
 * Converts a buffer to a bigint. Alias for beBufferToBigInt.
 * @param value The buffer to convert.
 * @returns The bigint representation of the buffer's contents.
 */
export function bufferToBigInt(value: Buffer | Uint8Array): bigint {
    return beBufferToBigInt(value)
}

/**
 * Converts a bigint to a buffer and fills with zeros if a valid
 * size (i.e. number of bytes) is specified. If the size is not defined,
 * it gets the size from the given bigint. If the specified size is smaller than
 * the size of the bigint (i.e. `minSize`), an error is thrown.
 * It uses big-endian byte order.
 * @param value The bigint to convert.
 * @param size The number of bytes of the buffer to return.
 * @returns The buffer representation of the bigint.
 */
export function beBigIntToBuffer(value: bigint, size?: number): Buffer {
    const hex = bigIntToHexadecimal(value)

    // Calculate the minimum buffer size required to represent 'n' in bytes.
    // Each hexadecimal character represents 4 bits, so 2 characters are 1 byte.
    const minSize = Math.ceil(hex.length / 2)

    if (!size) {
        size = minSize
    } else if (size < minSize) {
        throw Error(`Size ${size} is too small, need at least ${minSize} bytes`)
    }

    // Allocate buffer of the desired size, filled with zeros.
    const buffer = Buffer.alloc(size, 0)

    const fromHex = Buffer.from(hex, "hex")
    fromHex.copy(buffer, size - fromHex.length)

    return buffer
}

/**
 * Converts a bigint to a buffer and fills with zeros if a valid
 * size (i.e. number of bytes) is specified. If the size is not defined,
 * it gets the size from the given bigint. If the specified size is smaller than
 * the size of the bigint (i.e. `minSize`), an error is thrown.
 * It uses little-endian byte order.
 * @param value The bigint to convert.
 * @param size The number of bytes of the buffer to return.
 * @returns The buffer representation of the bigint in little-endian.
 */
export function leBigIntToBuffer(value: bigint, size?: number): Buffer {
    const hex = bigIntToHexadecimal(value)

    // Calculate the minimum buffer size required to represent 'n' in bytes.
    // Each hexadecimal character represents 4 bits, so 2 characters are 1 byte.
    const minSize = Math.ceil(hex.length / 2)

    if (!size) {
        size = minSize
    } else if (size < minSize) {
        throw Error(`Size ${size} is too small, need at least ${minSize} bytes`)
    }

    // Allocate buffer of the desired size, filled with zeros.
    const buffer = Buffer.alloc(size, 0)

    const fromHex = Buffer.from(hex, "hex").reverse()
    fromHex.copy(buffer, 0)

    return buffer
}

/**
 * Converts a bigint to a buffer. Alias for beBigIntToBuffer.
 * @param value The bigint to convert.
 * @returns The buffer representation of the bigint.
 */
export function bigIntToBuffer(value: bigint): Buffer {
    return beBigIntToBuffer(value)
}

/**
 * Converts a BigNumberish type to a bigint. If the input is already a bigint,
 * the return value will be the bigint itself, otherwise it will be converted
 * to a bigint using big-endian byte order.
 * @param value The BigNumberish value to convert.
 * @returns The bigint representation of the BigNumberish value.
 */
export function bigNumberishToBigInt(value: BigNumberish): bigint {
    requireBigNumberish(value, "value")

    if (isBuffer(value) || isUint8Array(value)) {
        return bufferToBigInt(value as Buffer)
    }

    return BigInt(value as BigNumber | number)
}

/**
 * Converts a BigNumberish type to a buffer. If the input is already a buffer,
 * the return value will be the buffer itself, otherwise it will be converted
 * to a buffer using big-endian byte order.
 * @param value The BigNumberish value to convert.
 * @returns The buffer representation of the BigNumberish value.
 */
export function bigNumberishToBuffer(value: BigNumberish): Buffer {
    requireBigNumberish(value, "value")

    if (isBuffer(value) || isUint8Array(value)) {
        return Buffer.from(value as Buffer)
    }

    return bigIntToBuffer(bigNumberishToBigInt(value))
}

/**
 * Converts a hexadecimal string to a buffer. The hexadecimal string
 * should not start with '0x' or '0X'. It keeps the bytes in the same order.
 * @param value The hexadecimal string to convert.
 * @returns The buffer representation of the hexadecimal string.
 */
export function hexadecimalToBuffer(value: string): Buffer {
    requireHexadecimal(value, "value", false)

    // Ensure even length before converting to buffer.
    if (value.length % 2 !== 0) {
        value = `0${value}`
    }

    return Buffer.from(value, "hex")
}

/**
 * Converts a buffer to a hexadecimal string. It accepts 'Buffer' or 'Uint8Array'.
 * The hexadecimal string will not start with '0x' or '0X'. It keeps the bytes in the same order.
 * @param value The buffer to convert.
 * @returns The converted hexadecimal string.
 */
export function bufferToHexadecimal(value: Buffer | Uint8Array): string {
    requireTypes(value, "value", ["Buffer", "Uint8Array"])

    return Buffer.from(value).toString("hex")
}

/**
 * Converts bytes to a base64 string. It accepts 'Buffer' or 'Uint8Array'.
 * @param value The bytes to convert.
 * @returns The converted base64 string.
 */
export function bufferToBase64(value: Buffer | Uint8Array): string {
    requireTypes(value, "value", ["Buffer", "Uint8Array"])

    return Buffer.from(value).toString("base64")
}

/**
 * Converts a base64 string to bytes (i.e. a buffer). This function does not check
 * if the input value is a valid base64 string. If there are unsupported characters
 * they will be ignored.
 * @param value The base64 string to convert.
 * @returns The converted buffer.
 */
export function base64ToBuffer(value: string): Buffer {
    requireString(value, "value")

    return Buffer.from(value, "base64")
}

/**
 * Converts text (utf8) to a base64 string.
 * @param value The text to convert.
 * @returns The converted base64 string.
 */
export function textToBase64(value: string): string {
    requireString(value, "value")

    return Buffer.from(value, "utf8").toString("base64")
}

/**
 * Converts a base64 string to text (utf8). This function does not check
 * if the input value is a valid base64 string. If there are unsupported characters
 * they could be ignored and the result may be unexpected.
 * @param value The base64 string to convert.
 * @returns The converted text.
 */
export function base64ToText(value: string): string {
    requireString(value, "value")

    return Buffer.from(value, "base64").toString("utf8")
}
