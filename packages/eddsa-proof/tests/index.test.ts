import { derivePublicKey } from "@zk-kit/eddsa-poseidon"
import { buildBn128 } from "@zk-kit/groth16"
import { decodeBytes32String, toBeHex } from "ethers"
import { poseidon2 } from "poseidon-lite"
import generate from "../src/generate"
import { EddsaProof } from "../src/types"
import verify from "../src/verify"

describe("EddsaProof", () => {
    const privateKey = Buffer.from("secret")
    const scope = "scope"

    let fullProof: EddsaProof
    let curve: any

    beforeAll(async () => {
        curve = await buildBn128()
        fullProof = await generate(privateKey, scope)
    }, 10_000)

    afterAll(async () => {
        await curve.terminate()
    })

    describe("# generate", () => {
        it("Should generate an Eddsa proof", async () => {
            const publicKey = derivePublicKey(privateKey)

            const commitment = poseidon2(publicKey)

            expect(fullProof.proof).toHaveLength(8)
            expect(decodeBytes32String(toBeHex(fullProof.scope, 32))).toBe(scope.toString())
            expect(fullProof.commitment).toBe(commitment.toString())
        })
    })

    describe("# verify", () => {
        it("Should verify a valid Eddsa proof", async () => {
            const response = await verify(fullProof)

            expect(response).toBe(true)
        })

        it("Should verify an invalid Eddsa proof", async () => {
            fullProof.commitment = "3"

            const response = await verify(fullProof)

            expect(response).toBe(false)
        })
    })
})
