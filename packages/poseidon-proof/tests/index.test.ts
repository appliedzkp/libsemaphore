import { buildBn128 } from "@zk-kit/groth16"
import { decodeBytes32String, toBeHex } from "ethers"
import {
    poseidon1,
    poseidon10,
    poseidon11,
    poseidon12,
    poseidon13,
    poseidon14,
    poseidon15,
    poseidon16,
    poseidon2,
    poseidon3,
    poseidon4,
    poseidon5,
    poseidon6,
    poseidon7,
    poseidon8,
    poseidon9
} from "poseidon-lite"
import generate from "../src/generate"
import hash from "../src/hash"
import { PoseidonProof } from "../src/types"
import verify from "../src/verify"

const poseidonFunctions = [
    poseidon1,
    poseidon2,
    poseidon3,
    poseidon4,
    poseidon5,
    poseidon6,
    poseidon7,
    poseidon8,
    poseidon9,
    poseidon10,
    poseidon11,
    poseidon12,
    poseidon13,
    poseidon14,
    poseidon15,
    poseidon16
]

const computePoseidon = (preimages: string[]) => poseidonFunctions[preimages.length - 1](preimages)

const preimages = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
const scope = "scope"
let curve: any
const proofs: Array<{ fullProof: PoseidonProof; digest: bigint }> = []

beforeAll(async () => {
    curve = await buildBn128()
    for (const preimage of preimages) {
        const currentPreimages = preimages.slice(0, preimage)
        const fullProof = await generate(currentPreimages, scope)
        const digest = computePoseidon(currentPreimages.map((preimage) => hash(preimage)))
        proofs.push({ fullProof, digest })
    }
}, 180_000)

afterAll(async () => {
    await curve.terminate()
})

describe("PoseidonProof", () => {
    it("should generate a Poseidon proof from 1 to 16 preimages", async () => {
        for (const { fullProof, digest } of proofs) {
            expect(fullProof.proof).toHaveLength(8)
            expect(decodeBytes32String(toBeHex(fullProof.scope, 32))).toBe(scope.toString())
            expect(fullProof.digest).toBe(digest.toString())
        }
    })

    it("Should verify a Poseidon proof from 1 to 16 preimage(s)", async () => {
        proofs.forEach(async ({ fullProof }) => {
            await expect(verify(fullProof)).resolves.toBe(true)
        })
    })

    it("Should verify an invalid Poseidon proof", async () => {
        const { fullProof } = proofs[0]
        fullProof.digest = "3"

        const response = await verify(fullProof)

        expect(response).toBe(false)
    })
})
