import { babyjub, eddsa } from "circomlibjs"
import { Buffer } from "buffer"
import { crypto } from "@zk-kit/utils"
import { utils } from "ffjavascript"
import { r, packPoint, Point } from "@zk-kit/baby-jubjub"
import {
    EdDSAPoseidon,
    derivePublicKey,
    deriveSecretScalar,
    packPublicKey,
    packSignature,
    signMessage,
    unpackPublicKey,
    unpackSignature,
    verifySignature
} from "../src/eddsa-poseidon-blake-1"

import { Signature } from "../src/types"
import { isPoint, isSignature } from "../src/utils"

function stringifyPoint(publicKey: Point): Point<string> {
    return [publicKey[0].toString(), publicKey[1].toString()]
}

function stringifySignature(signature: Signature): Signature<string> {
    return {
        R8: [signature.R8[0].toString(), signature.R8[1].toString()],
        S: signature.S.toString()
    }
}

describe("EdDSAPoseidon", () => {
    const privateKey = "secret"
    const message = BigInt(2)

    it("Should derive a public key from a private key (string)", async () => {
        const publicKey = derivePublicKey(privateKey)

        const circomlibPublicKey = eddsa.prv2pub(privateKey)

        expect(publicKey[0]).toBe(circomlibPublicKey[0])
        expect(publicKey[1]).toBe(circomlibPublicKey[1])
    })

    it("Should derive a public key from a private key (Buffer)", async () => {
        const privateKey = Buffer.from("secret")

        const publicKey = derivePublicKey(privateKey)

        const circomlibPublicKey = eddsa.prv2pub(privateKey)

        expect(publicKey[0]).toBe(circomlibPublicKey[0])
        expect(publicKey[1]).toBe(circomlibPublicKey[1])
    })

    it("Should derive a public key from a private key (Uint8Array)", async () => {
        const privateKey = new Uint8Array([3, 2])

        const publicKey = derivePublicKey(privateKey)

        const circomlibPublicKey = eddsa.prv2pub(Buffer.from(privateKey))

        expect(publicKey[0]).toBe(circomlibPublicKey[0])
        expect(publicKey[1]).toBe(circomlibPublicKey[1])
    })

    it("Should throw an error if the secret type is not supported", async () => {
        const privateKey = BigInt(32)

        const fun = () => derivePublicKey(privateKey as any)

        expect(fun).toThrow(`Parameter 'privateKey' is none of the following types: Buffer, Uint8Array, string`)
    })

    it("Should sign a message (bigint)", async () => {
        const signature = signMessage(privateKey, message)

        const circomlibSignature = eddsa.signPoseidon(privateKey, message)

        expect(signature.R8[0]).toBe(circomlibSignature.R8[0])
        expect(signature.R8[1]).toBe(circomlibSignature.R8[1])
        expect(signature.S).toBe(circomlibSignature.S)
    })

    it("Should sign a message (number)", async () => {
        const message = 22

        const signature = signMessage(privateKey, message)

        const circomlibSignature = eddsa.signPoseidon(privateKey, BigInt(message))

        expect(signature.R8[0]).toBe(circomlibSignature.R8[0])
        expect(signature.R8[1]).toBe(circomlibSignature.R8[1])
        expect(signature.S).toBe(circomlibSignature.S)
    })

    it("Should sign a message (hexadecimal)", async () => {
        const message = "0x12"

        const signature = signMessage(privateKey, message)

        const circomlibSignature = eddsa.signPoseidon(privateKey, BigInt(message))

        expect(signature.R8[0]).toBe(circomlibSignature.R8[0])
        expect(signature.R8[1]).toBe(circomlibSignature.R8[1])
        expect(signature.S).toBe(circomlibSignature.S)
    })

    it("Should sign a message (buffer)", async () => {
        const message = Buffer.from("message")

        const signature = signMessage(privateKey, message)

        const circomlibSignature = eddsa.signPoseidon(privateKey, BigInt(`0x${message.toString("hex")}`))

        expect(signature.R8[0]).toBe(circomlibSignature.R8[0])
        expect(signature.R8[1]).toBe(circomlibSignature.R8[1])
        expect(signature.S).toBe(circomlibSignature.S)
    })

    it("Should sign a message (string)", async () => {
        const message = "message"

        const signature = signMessage(privateKey, message)

        const circomlibSignature = eddsa.signPoseidon(privateKey, BigInt(`0x${Buffer.from(message).toString("hex")}`))

        expect(signature.R8[0]).toBe(circomlibSignature.R8[0])
        expect(signature.R8[1]).toBe(circomlibSignature.R8[1])
        expect(signature.S).toBe(circomlibSignature.S)
    })

    it("Should throw an error if the message type is not supported", async () => {
        const message = true

        const fun = () => signMessage(privateKey, message as any)

        expect(fun).toThrow(`Parameter 'message' is none of the following types: bignumberish, string`)
    })

    it("Should throw an error if the message is larger than 32 Bytes [string]", async () => {
        const message = "abcdefghijklmnopqrstuvwxyz1234567"

        const fun = () => signMessage(privateKey, message)

        expect(fun).toThrow(`Message length is larger than 32 bytes`)
    })

    it("Should throw an error if the message is larger than 32 Bytes [number]", async () => {
        const message = 2 ** 255

        const fun = () => signMessage(privateKey, message)

        expect(fun).toThrow(`Message length is larger than 32 bytes`)
    })

    it("Should throw an error if the message is larger than 32 Bytes [-number]", async () => {
        const message = -(2n ** 255n + 1n)

        const fun = () => signMessage(privateKey, message)

        expect(fun).toThrow(`Message length is larger than 32 bytes`)
    })

    it("Should verify a signature (numeric)", async () => {
        const publicKey = derivePublicKey(privateKey)
        const signature = signMessage(privateKey, message)

        expect(verifySignature(message, signature, publicKey)).toBeTruthy()
    })

    it("Should verify a signature (stringified)", async () => {
        const publicKey = stringifyPoint(derivePublicKey(privateKey))
        const signature = stringifySignature(signMessage(privateKey, message))

        expect(verifySignature(message, signature, publicKey)).toBeTruthy()
    })

    it("Should not verify a signature if the public key is malformed", async () => {
        const publicKey = derivePublicKey(privateKey)
        const signature = signMessage(privateKey, message)

        publicKey[1] = 3 as any

        expect(verifySignature(message, signature, publicKey)).toBeFalsy()
    })

    it("Should not verify a signature if the signature is malformed", async () => {
        const publicKey = derivePublicKey(privateKey)
        const signature = signMessage(privateKey, message)

        signature.S = 3 as any

        expect(verifySignature(message, signature, publicKey)).toBeFalsy()
    })

    it("Should not verify a signature if the signature is not on the curve", async () => {
        const publicKey = derivePublicKey(privateKey)
        const signature = signMessage(privateKey, message)

        signature.R8[1] = BigInt(3)

        expect(verifySignature(message, signature, publicKey)).toBeFalsy()
    })

    it("Should not verify a signature if the public key is not on the curve", async () => {
        const publicKey = derivePublicKey(privateKey)
        const signature = signMessage(privateKey, message)

        publicKey[1] = BigInt(3)

        expect(verifySignature(message, signature, publicKey)).toBeFalsy()
    })

    it("Should not verify a signature S value exceeds the predefined sub order", async () => {
        const publicKey = derivePublicKey(privateKey)
        const signature = signMessage(privateKey, message)

        signature.S = BigInt("3421888242871839275222246405745257275088614511777268538073601725287587578984328")

        expect(verifySignature(message, signature, publicKey)).toBeFalsy()
    })

    it("Should derive a public key from N random private keys", async () => {
        for (let i = 0, len = 10; i < len; i += 1) {
            const privateKey = Buffer.from(crypto.getRandomValues(32))
            const publicKey = derivePublicKey(privateKey)
            const circomlibPublicKey = eddsa.prv2pub(privateKey)

            expect(publicKey[0]).toBe(circomlibPublicKey[0])
            expect(publicKey[1]).toBe(circomlibPublicKey[1])
        }
    })

    it("Should pack a public key (numeric)", async () => {
        const publicKey = derivePublicKey(privateKey)

        const packedPublicKey = packPublicKey(publicKey)

        const expectedPackedPublicKey = babyjub.packPoint(publicKey)

        expect(packedPublicKey).toBe(utils.leBuff2int(expectedPackedPublicKey))
    })

    it("Should pack a public key (stringified)", async () => {
        const publicKey = stringifyPoint(derivePublicKey(privateKey))

        const packedPublicKey = packPublicKey(publicKey)

        const expectedPackedPublicKey = babyjub.packPoint([BigInt(publicKey[0]), BigInt(publicKey[1])])

        expect(packedPublicKey).toBe(utils.leBuff2int(expectedPackedPublicKey))
    })

    it("Should not pack a public key if the public key is not on the curve", async () => {
        const publicKey = derivePublicKey(privateKey)

        publicKey[1] = BigInt(3)

        const fun = () => packPublicKey(publicKey)

        expect(fun).toThrow("Invalid public key")
    })

    it("Should unpack a packed public key", async () => {
        const publicKey = derivePublicKey(privateKey)

        const packedPublicKey = packPublicKey(publicKey)
        const unpackedPublicKey = unpackPublicKey(packedPublicKey)

        expect(unpackedPublicKey[0]).toBe(publicKey[0])
        expect(unpackedPublicKey[1]).toBe(publicKey[1])
    })

    it("Should not unpack a public key if the public key type is not supported", async () => {
        const fun = () => unpackPublicKey("e")

        expect(fun).toThrow(`Parameter 'publicKey' is not a bignumber-ish`)
    })

    it("Should not unpack a public key if the public key does not correspond to a valid point on the curve", async () => {
        const invalidPublicKey = packPoint([BigInt("0"), BigInt(r + BigInt(1))]).toString()

        const fun = () => unpackPublicKey(invalidPublicKey)

        expect(fun).toThrow("Invalid public key")
    })

    it("Should pack a signature (numeric)", async () => {
        const signature = signMessage(privateKey, message)

        const packedSignature = packSignature(signature)
        expect(packedSignature).toHaveLength(64)

        const circomlibSignature = eddsa.signPoseidon(privateKey, message)
        const circomlibPackedSignature = eddsa.packSignature(circomlibSignature)

        expect(packedSignature).toEqual(circomlibPackedSignature)
    })

    it("Should pack a signature (stringified)", async () => {
        const signature = signMessage(privateKey, message)

        const packedSignature = packSignature(stringifySignature(signature))
        expect(packedSignature).toHaveLength(64)

        const circomlibSignature = eddsa.signPoseidon(privateKey, message)
        const circomlibPackedSignature = eddsa.packSignature(circomlibSignature)

        expect(packedSignature).toEqual(circomlibPackedSignature)
    })

    it("Should still pack an incorrect signature", async () => {
        const signature = signMessage(privateKey, message)

        signature.S = BigInt(3)

        const packedSignature = packSignature(signature)
        expect(packedSignature).toHaveLength(64)
    })

    it("Should not pack a signature if the signature is not on the curve", async () => {
        const signature = signMessage(privateKey, message)

        signature.R8[1] = BigInt(3)

        const fun = () => packSignature(signature)

        expect(fun).toThrow("Invalid signature")
    })

    it("Should not pack a signature S value exceeds the predefined sub order", async () => {
        const signature = signMessage(privateKey, message)

        signature.S = BigInt("3421888242871839275222246405745257275088614511777268538073601725287587578984328")

        const fun = () => packSignature(signature)

        expect(fun).toThrow("Invalid signature")
    })

    it("Should unpack a packed signature", async () => {
        const signature = signMessage(privateKey, message)

        const packedSignature = packSignature(signature)

        const unpackedSignature = unpackSignature(packedSignature)
        expect(unpackedSignature).toEqual(signature)

        const circomlibSignature = eddsa.signPoseidon(privateKey, message)
        const circomlibUnpackedSignature = eddsa.unpackSignature(packedSignature)
        expect(circomlibSignature).toEqual(circomlibUnpackedSignature)
    })

    it("Should not unpack a packed signature of the wrong length", async () => {
        const signature = signMessage(privateKey, message)

        const packedSignature = packSignature(signature)

        const fun = () => unpackSignature(packedSignature.subarray(0, 63))
        expect(fun).toThrow("Packed signature must be 64 bytes")
    })

    it("Should not unpack a packed signature with point malformed", async () => {
        const signature = signMessage(privateKey, message)

        const packedSignature = packSignature(signature)
        packedSignature.set([1], 3)

        const fun = () => unpackSignature(packedSignature)
        expect(fun).toThrow("Invalid packed signature point")
    })

    it("Should still unpack a packed signature with scalar malformed", async () => {
        const signature = signMessage(privateKey, message)

        const packedSignature = packSignature(signature)
        packedSignature.set([1], 35)

        expect(() => unpackSignature(packedSignature)).not.toThrow()
    })

    it("Should handle a signature with values smaller than 32 bytes", async () => {
        const signature = signMessage(privateKey, message)

        // S is the only value which we can easily make artifically small, since
        // R8 has to be a point on the curve.
        // Note that overly-large values also ruled out by the inCurve check on
        // R8 and the subOrder check on S.
        signature.S = BigInt(3)

        const packedSignature = packSignature(signature)

        const unpackedSignature = unpackSignature(packedSignature)
        expect(unpackedSignature).toEqual(signature)
    })

    it("Should create an EdDSAPoseidon instance", async () => {
        const eddsa = new EdDSAPoseidon(privateKey)

        const signature = eddsa.signMessage(message)

        expect(typeof eddsa.privateKey).toBe("string")
        expect(eddsa.privateKey).toBe(privateKey)
        expect(eddsa.secretScalar).toBe(deriveSecretScalar(privateKey))
        expect(eddsa.packedPublicKey).toBe(packPublicKey(eddsa.publicKey))
        expect(eddsa.verifySignature(message, signature)).toBeTruthy()
    })

    it("Should create an EdDSAPoseidon instance with a random private key", async () => {
        const eddsa = new EdDSAPoseidon()

        const signature = eddsa.signMessage(message)

        expect(typeof eddsa.privateKey).toBe("object")
        expect(eddsa.privateKey).toHaveLength(32)
        expect(eddsa.secretScalar).toBe(deriveSecretScalar(eddsa.privateKey))
        expect(eddsa.packedPublicKey).toBe(packPublicKey(eddsa.publicKey))
        expect(eddsa.verifySignature(message, signature)).toBeTruthy()
    })
})

describe("eddsa-poseidon.utils", () => {
    it("Should identify points in different forms", async () => {
        expect(isPoint(undefined as any as Point)).toBeFalsy()
        expect(isPoint(123 as any as Point)).toBeFalsy()
        expect(isPoint(["1", "2"])).toBeTruthy()
        expect(isPoint(["0xa1", "0xb2"])).toBeTruthy()
        expect(isPoint(["1", BigInt("2")])).toBeTruthy()
        expect(isPoint([BigInt("1"), "2"])).toBeTruthy()
        expect(isPoint([BigInt("1"), BigInt("2")])).toBeTruthy()
        expect(isPoint(["1", "2", "3"] as any as Point)).toBeFalsy()
        expect(isPoint({ x: "1", y: "2" } as any as Point)).toBeFalsy()
    })

    it("Should identify signatures in different forms", async () => {
        expect(isSignature(undefined as any as Signature)).toBeFalsy()
        expect(isSignature(123 as any as Signature)).toBeFalsy()
        expect(isSignature({ R8: ["1", "2"], S: "3" })).toBeTruthy()
        expect(isSignature({ R8: ["0xa1", "0xb2"], S: "0xc3" })).toBeTruthy()
        expect(isSignature({ R8: [BigInt("1"), BigInt("2")], S: BigInt("3") })).toBeTruthy()
        expect(isSignature({ R8: ["1", "2", "3"], S: "4" } as any as Signature)).toBeFalsy()
        expect(isSignature({ R8: ["1", "2"], SS: "3" } as any as Signature)).toBeFalsy()
    })
})
