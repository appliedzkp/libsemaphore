/* This script benchmarks three implementations of Merkle Trees—Incremental Merkle Tree,
Lean Incremental Merkle Tree, and Sparse Merkle Tree—to compare their performance across
various operations such as adding leaves, generating proofs, and verifying proofs.
The results are saved as .html files (charts and tables) for analysis. */
import b from "benny"
import { poseidon2 } from "poseidon-lite"
import sha256 from "crypto-js/sha256"
import winston from "winston"
import path from "path"

import { IMT } from "@zk-kit/imt"
import { LeanIMT } from "@zk-kit/lean-imt"
import { ChildNodes, SMT } from "@zk-kit/smt"
import { IMTMerkleProof } from "../packages/imt/src/types"
import { LeanIMTMerkleProof } from "../packages/lean-imt/src/types"
import { MerkleProof } from "../packages/smt/src/types"

const logger = winston.createLogger({
    level: "error",
    format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
    transports: [new winston.transports.File({ filename: path.join(__dirname, "error.log") })]
})

/*  Main Function:
        This function runs the benchmarks for all three Merkle tree implementations:
        - Incremental Merkle Tree using IMT
        - Lean Incremental Merkle Tree using LeanIMT (Excluded the delete benchmark because
          the leaf implementation does not exist)
        - Sparse Merkle Tree using SMT
*/
export default function run(treeDepth: number, numberOfLeaves: number) {
    function getNodesSample(numberOfLeaves: number, numberOfElements: number): number[] {
        const sample: number[] = []
        const usedNumbers = new Set<number>()
        // Generate unique random numbers to sample leaves
        while (sample.length < numberOfElements) {
            const randomNumber = Math.floor(
                ((Math.random() + numberOfElements) * (Math.random() + numberOfLeaves)) % numberOfLeaves
            )

            if (!usedNumbers.has(randomNumber)) {
                sample.push(randomNumber)
                usedNumbers.add(randomNumber)
            }
        }

        return sample
    }

    const incrementalMerkleTree = new IMT(poseidon2, numberOfLeaves, 0, 2)
    const leanIncrementalMerkleTree = new LeanIMT((a, b) => poseidon2([a, b]))
    const hash = (childNodes: ChildNodes) => sha256(childNodes.join("")).toString()
    const sparseMerkleTree = new SMT(hash)
    for (let i = 0; i < numberOfLeaves; i += 1) {
        incrementalMerkleTree.insert(i)
        leanIncrementalMerkleTree.insert(BigInt(i))
        sparseMerkleTree.add(i.toString(16), Math.floor(Math.random() * 10).toString(16))
    }

    const incrementalMerkleTree2 = new IMT(poseidon2, treeDepth, 0, 2)
    const leanIncrementalMerkleTree2 = new LeanIMT((a, b) => poseidon2([a, b]))
    const hash2 = (childNodes: ChildNodes) => sha256(childNodes.join("")).toString()
    const sparseMerkleTree2 = new SMT(hash2)

    let leafIMT = 0
    let leafLeanIMT = 0
    let leafSMT = 0
    /*  Number of leaves to take as sample to benchmark.
        It acts as a limit to stop doing the operation (delete) or restart the cycle
        counter controller (update, proof, verification) in a benchmark since
        the benny suite does not have the method to limit the maximum of operations
        of the benchmark.
    */
    const samples = numberOfLeaves * 0.5
    // The set of keys to do benchmarks (update, proof, verification and delete)
    const sample = getNodesSample(numberOfLeaves, samples)

    /* Benchmarking Add Operation:
    The following code benchmarks how efficiently each tree adds leaves. */
    let name = `add-merkle-trees-${numberOfLeaves}`
    b.suite(
        name,
        b.add(`IMT - Add ${numberOfLeaves} leaves`, () => {
            try {
                if (leafIMT < numberOfLeaves) {
                    incrementalMerkleTree2.insert(leafIMT)
                    leafIMT += 1
                }
            } catch (error) {
                logger.error(name)
                logger.error(error)
            }
        }),
        b.add(`LeanIMT - Add ${numberOfLeaves} leaves`, () => {
            try {
                leanIncrementalMerkleTree2.insert(BigInt(leafLeanIMT))
                leafLeanIMT += 1
            } catch (error) {
                logger.error(name)
                logger.error(error)
            }
        }),
        b.add(`SparseMT - Add ${numberOfLeaves} leaves`, () => {
            try {
                sparseMerkleTree2.add(leafSMT.toString(16), Math.floor(Math.random() * 10).toString())
                leafSMT += 1
            } catch (error) {
                logger.error(name)
                logger.error(error)
            }
        }),
        b.cycle(),
        b.complete(),
        b.save({ folder: "benchmarks/results", file: name, version: "1.0.0", details: true }),
        b.save({ folder: "benchmarks/results", file: name, format: "chart.html", details: true }),
        b.save({ folder: "benchmarks/results", file: name, format: "table.html", details: true })
    ).catch((error) => {
        logger.error(name)
        logger.error(error)
    })

    /*  Benchmarking Proof Generation:
            This section benchmarks proof generation for each tree type. */
    leafIMT = 0
    leafLeanIMT = 0
    leafSMT = 0
    name = `proof-generation-merkle-trees-${numberOfLeaves}`
    b.suite(
        name,
        b.add(`IMT - Generated ${samples} proofs`, () => {
            try {
                if (leafIMT < samples) {
                    incrementalMerkleTree.createProof(sample[leafIMT])
                } else {
                    leafIMT = -1
                }
                leafIMT += 1
            } catch (error) {
                logger.error(name)
                logger.error(error)
            }
        }),
        b.add(`LeanIMT - Generated ${samples} proofs`, () => {
            try {
                if (leafLeanIMT < samples) {
                    leanIncrementalMerkleTree.generateProof(sample[leafLeanIMT])
                } else {
                    leafLeanIMT = -1
                }
                leafLeanIMT += 1
            } catch (error) {
                logger.error(name)
                logger.error(error)
            }
        }),
        b.add(`SparseMT - Generated ${samples} proofs`, () => {
            try {
                if (leafSMT < samples) {
                    sparseMerkleTree.createProof(sample[leafSMT].toString(16))
                } else {
                    leafSMT = -1
                }
                leafSMT += 1
            } catch (error) {
                logger.error(name)
                logger.error(error)
            }
        }),
        b.cycle(),
        b.complete(),
        b.save({ folder: "benchmarks/results", file: name, version: "1.0.0", details: true }),
        b.save({ folder: "benchmarks/results", file: name, format: "chart.html", details: true }),
        b.save({ folder: "benchmarks/results", file: name, format: "table.html", details: true })
    ).catch((error) => {
        logger.error(name)
        logger.error(error)
    })

    /*  Proof sample generation:
            Produces a set of proofs that will be used in the proof verification benchmark */
    const proofsIMT: IMTMerkleProof[] = []
    const proofsLeanIMT: LeanIMTMerkleProof[] = []
    const proofsSMT: MerkleProof[] = []
    for (let i = 0; i < samples; i += 1) {
        try {
            proofsIMT.push(incrementalMerkleTree.createProof(sample[i]))
            proofsLeanIMT.push(leanIncrementalMerkleTree.generateProof(sample[i]))
            proofsSMT.push(sparseMerkleTree.createProof(sample[i].toString(16)))
        } catch (error) {
            logger.error("Proof sample generation")
            logger.error(error)
        }
    }

    /*  Benchmarking Proof Verification:
            This section benchmarks proof verification for each tree type. */
    leafIMT = 0
    leafLeanIMT = 0
    leafSMT = 0
    name = `proof-verification-merkle-trees-${numberOfLeaves}`
    b.suite(
        name,
        b.add(`IMT - Verified ${samples} proofs`, () => {
            try {
                if (leafIMT < samples) {
                    incrementalMerkleTree.verifyProof(proofsIMT[leafIMT])
                }
                leafIMT += 1
            } catch (error) {
                logger.error(name)
                logger.error(error)
            }
        }),
        b.add(`LeanIMT - Verified ${samples} proofs`, () => {
            try {
                if (leafLeanIMT < samples) {
                    leanIncrementalMerkleTree.verifyProof(proofsLeanIMT[leafLeanIMT])
                }
                leafLeanIMT += 1
            } catch (error) {
                logger.error(name)
                logger.error(error)
            }
        }),
        b.add(`SparseMT - Verified ${samples} proofs`, () => {
            try {
                if (leafSMT < samples) {
                    sparseMerkleTree.verifyProof(proofsSMT[leafSMT])
                }
                leafSMT += 1
            } catch (error) {
                logger.error(name)
                logger.error(error)
            }
        }),
        b.cycle(),
        b.complete(),
        b.save({ folder: "benchmarks/results", file: name, version: "1.0.0", details: true }),
        b.save({ folder: "benchmarks/results", file: name, format: "chart.html", details: true }),
        b.save({ folder: "benchmarks/results", file: name, format: "table.html", details: true })
    ).catch((error) => {
        logger.error(name)
        logger.error(error)
    })

    /*  Benchmarking update operation:
            The following code benchmarks how efficiently each tree updates leaves. */
    leafIMT = 0
    leafLeanIMT = 0
    leafSMT = 0
    name = `update-merkle-trees-${numberOfLeaves}`
    b.suite(
        name,
        b.add(`IMT - Updated ${samples} leaves`, () => {
            try {
                if (leafIMT < samples) {
                    incrementalMerkleTree.update(sample[leafIMT], Math.trunc(Math.random()))
                } else {
                    leafIMT = 0
                }
                leafIMT += 1
            } catch (error) {
                logger.error(name)
                logger.error(error)
            }
        }),
        b.add(`LeanIMT - Updated ${samples} leaves`, () => {
            try {
                if (leafLeanIMT < numberOfLeaves) {
                    leanIncrementalMerkleTree.update(sample[leafLeanIMT], BigInt(Math.trunc(Math.random())))
                }
                leafLeanIMT += 1
            } catch (error) {
                logger.error(name)
                logger.error(error)
            }
        }),
        b.add(`SparseMT - Updated ${samples} leaves`, () => {
            try {
                if (leafSMT < samples) {
                    sparseMerkleTree.update(sample[leafSMT].toString(16), Math.trunc(Math.random()).toString())
                } else {
                    leafSMT = 0
                }
                leafSMT += 1
            } catch (error) {
                logger.error(name)
                logger.error(error)
            }
        }),
        b.cycle(),
        b.complete(),
        b.save({ folder: "benchmarks/results", file: name, version: "1.0.0", details: true }),
        b.save({ folder: "benchmarks/results", file: name, format: "chart.html", details: true }),
        b.save({ folder: "benchmarks/results", file: name, format: "table.html", details: true })
    ).catch((error) => {
        logger.error(name)
        logger.error(error)
    })

    /*  Benchmarking delete operation:
            The following code benchmarks how efficiently each tree deletes leaves. */
    leafIMT = 0
    leafSMT = 0
    name = `delete-merkle-trees-${numberOfLeaves}`
    b.suite(
        name,
        b.add(`IMT - Deleted ${samples} leaves`, () => {
            try {
                if (leafIMT < samples) {
                    incrementalMerkleTree.delete(sample[leafIMT])
                }
            } catch (error) {
                logger.error(name)
                logger.error(error)
            }
            leafIMT += 1
        }),
        b.add(`SparseMT - Deleted ${samples} leaves`, () => {
            try {
                if (leafSMT < samples) {
                    sparseMerkleTree.delete(sample[leafSMT].toString())
                }
            } catch (error) {
                logger.error(name)
                logger.error(error)
            }
            leafSMT += 1
        }),
        b.cycle(),
        b.complete(),

        b.save({ folder: "benchmarks/results", file: name, version: "1.0.0", details: true }),
        b.save({ folder: "benchmarks/results", file: name, format: "chart.html", details: true }),
        b.save({ folder: "benchmarks/results", file: name, format: "table.html", details: true })
    ).catch((error) => {
        logger.error(name)
        logger.error(error)
    })
}
