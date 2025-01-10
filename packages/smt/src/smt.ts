import { checkHex, getFirstCommonElements, getIndexOfLastNonZeroElement, keyToPath } from "./utils"
import { ChildNodes, EntryMark, HashFunction, Key, Value, Node, Siblings, EntryResponse, MerkleProof } from "./types"

/**
 * SparseMerkleTree class provides all the functions to create a sparse Merkle tree
 * and to take advantage of its features: {@linkcode SMT.add}, {@linkcode SMT.get},
 * {@linkcode SMT.update}, {@linkcode SMT.delete}, {@linkcode SMT.createProof},
 * {@linkcode SMT.verifyProof}.
 * To better understand the code below it may be useful to describe the terminology used:
 * * **nodes**: every node in the tree is the hash of the two child nodes (`H(x, y)`);
 * * **root node**: the root node is the top hash and since it represents the whole data
 * structure it can be used to certify its integrity;
 * * **leaf nodes**: every leaf node is the hash of a key/value pair and an additional
 * value to mark the node as leaf node (`H(x, y, 1)`);
 * * **entry**: a tree entry is a key/value pair used to create the leaf nodes;
 * * **zero nodes**: a zero node is a hash of zeros and in this implementation `H(0,0) = 0`;
 * * **siblings**: the children of a parent node are siblings;
 * * **path**: every entry key is a number < 2^256 that can be converted in a binary number,
 * and this binary number is the path used to place the entry in the tree (1 or 0 define the
 * child node to choose);
 * * **matching node**: when an entry is not found and the path leads to another existing entry,
 * this entry is a matching entry and it has some of the first bits in common with the entry not found;
 * * **depth**: the depth of a node is the length of the path to its root.
 */
export default class SMT {
    // Hash function used to hash the child nodes.
    private hash: HashFunction
    // Value for zero nodes.
    private zeroNode: Node
    // Additional entry value to mark the leaf nodes.
    private entryMark: EntryMark
    // If true it sets `BigInt` type as default type of the tree hashes.
    private bigNumbers: boolean
    // Key/value map in which the key is a node of the tree and
    // the value is an array of child nodes. When the node is
    // a leaf node the child nodes are an entry (key/value) of the tree.
    private nodes: Map<Node, ChildNodes>

    // The root node of the tree.
    root: Node

    /**
     * Initializes the SparseMerkleTree attributes.
     * @param hash Hash function used to hash the child nodes.
     * @param bigNumbers BigInt type enabling.
     */
    constructor(hash: HashFunction, bigNumbers = false) {
        if (bigNumbers) {
            /* istanbul ignore next */
            if (typeof BigInt !== "function") {
                throw new Error("Big numbers are not supported")
            }

            if (typeof hash([BigInt(1), BigInt(1)]) !== "bigint") {
                throw new Error("The hash function must return a big number")
            }
        } else if (!checkHex(hash(["1", "1"]) as string)) {
            throw new Error("The hash function must return a hexadecimal")
        }

        this.hash = hash
        this.bigNumbers = bigNumbers
        this.zeroNode = bigNumbers ? BigInt(0) : "0"
        this.entryMark = bigNumbers ? BigInt(1) : "1"
        this.nodes = new Map()

        this.root = this.zeroNode // The root node is initially a zero node.
    }

    /**
     * Gets a key and if the key exists in the tree the function returns the
     * value, otherwise it returns 'undefined'.
     * @param key A key of a tree entry.
     * @returns A value of a tree entry or 'undefined'.
     */
    get(key: Key): Value | undefined {
        this.checkParameterType(key)

        const { entry } = this.retrieveEntry(key)

        return entry[1]
    }

    /**
     * Adds a new entry in the tree. It retrieves a matching entry
     * or a zero node with a top-down approach and then it updates all the
     * hashes of the nodes in the path of the new entry with a bottom-up approach.
     * @param key The key of the new entry.
     * @param value The value of the new entry.
     */
    add(key: Key, value: Value) {
        this.checkParameterType(key)
        this.checkParameterType(value)

        const { entry, matchingEntry, siblings } = this.retrieveEntry(key)

        if (entry[1] !== undefined) {
            throw new Error(`Key "${key}" already exists`)
        }

        const path = keyToPath(key)
        // If there is a matching entry its node is saved, otherwise
        // the node is a zero node. This node is used below as the first node
        // (starting from the bottom of the tree) to obtain the new nodes
        // up to the root.
        const node = matchingEntry ? this.hash(matchingEntry) : this.zeroNode

        // If there are siblings it deletes all the nodes of the path.
        // These nodes will be re-created below with the new hashes.
        if (siblings.length > 0) {
            this.deleteOldNodes(node, path, siblings)
        }

        // If there is a matching entry, further N zero siblings are added
        // in the `siblings` array, followed by the matching node itself.
        // N is the number of the first matching bits of the paths.
        // This is helpful in the non-membership proof verification
        // as explained in the function below.
        if (matchingEntry) {
            const matchingPath = keyToPath(matchingEntry[0])

            for (let i = siblings.length; matchingPath[i] === path[i]; i += 1) {
                siblings.push(this.zeroNode)
            }

            siblings.push(node)
        }

        // Adds the new entry and re-creates the nodes of the path with the new hashes
        // with a bottom-up approach. The `addNewNodes` function returns the last node
        // added, which is the root node.
        const newNode = this.hash([key, value, this.entryMark])
        this.nodes.set(newNode, [key, value, this.entryMark])
        this.root = this.addNewNodes(newNode, path, siblings)
    }

    /**
     * Updates a value of an entry in the tree. Also in this case
     * all the hashes of the nodes in the path of the entry are updated
     * with a bottom-up approach.
     * @param key The key of the entry.
     * @param value The value of the entry.
     */
    update(key: Key, value: Value) {
        this.checkParameterType(key)
        this.checkParameterType(value)

        const { entry, siblings } = this.retrieveEntry(key)

        if (entry[1] === undefined) {
            throw new Error(`Key "${key}" does not exist`)
        }

        const path = keyToPath(key)

        // Deletes the old entry and all the nodes in its path.
        const oldNode = this.hash(entry)
        this.nodes.delete(oldNode)
        this.deleteOldNodes(oldNode, path, siblings)

        // Adds the new entry and re-creates the nodes of the path
        // with the new hashes.
        const newNode = this.hash([key, value, this.entryMark])
        this.nodes.set(newNode, [key, value, this.entryMark])
        this.root = this.addNewNodes(newNode, path, siblings)
    }

    /**
     * Deletes an entry in the tree. Also in this case all the hashes of
     * the nodes in the path of the entry are updated with a bottom-up approach.
     * @param key The key of the entry.
     */
    delete(key: Key) {
        this.checkParameterType(key)

        const { entry, siblings } = this.retrieveEntry(key)

        if (entry[1] === undefined) {
            throw new Error(`Key "${key}" does not exist`)
        }

        const path = keyToPath(key)

        // Deletes the entry.
        const node = this.hash(entry)
        this.nodes.delete(node)

        this.root = this.zeroNode

        // If there are siblings it deletes the nodes of the path and
        // re-creates them with the new hashes.
        if (siblings.length > 0) {
            this.deleteOldNodes(node, path, siblings)

            // If the last siblings is not a leaf node, it adds all the
            // nodes of the path starting from a zero node, otherwise
            // it removes the last non-zero siblings from the `siblings`
            // array and it starts from it by skipping the last zero nodes.
            if (!this.isLeaf(siblings[siblings.length - 1])) {
                this.root = this.addNewNodes(this.zeroNode, path, siblings)
            } else {
                const firstSibling = siblings.pop() as Node
                const i = getIndexOfLastNonZeroElement(siblings)

                this.root = this.addNewNodes(firstSibling, path, siblings, i)
            }
        }
    }

    /**
     * Creates a proof to prove the membership or the non-membership
     * of a tree entry.
     * @param key A key of an existing or a non-existing entry.
     * @returns The membership or the non-membership proof.
     */
    createProof(key: Key): MerkleProof {
        this.checkParameterType(key)

        const { entry, matchingEntry, siblings } = this.retrieveEntry(key)

        // If the key exists the function returns a membership proof, otherwise it
        // returns a non-membership proof with the matching entry.
        return {
            entry,
            matchingEntry,
            siblings,
            root: this.root,
            membership: !!entry[1]
        }
    }

    /**
     * Verifies a membership or a non-membership proof.
     * @param merkleProof The proof to verify.
     * @returns True if the proof is valid, false otherwise.
     */
    verifyProof(merkleProof: MerkleProof): boolean {
        // If there is not a matching entry it simply obtains the root
        // hash by using the siblings and the path of the key.
        if (!merkleProof.matchingEntry) {
            const path = keyToPath(merkleProof.entry[0])
            // If there is not an entry value the proof is a non-membership proof,
            // and in this case, since there is not a matching entry, the node
            // is a zero node. If there is an entry value the proof is a
            // membership proof and the node is the hash of the entry.
            const node = merkleProof.entry[1] !== undefined ? this.hash(merkleProof.entry) : this.zeroNode
            const root = this.calculateRoot(node, path, merkleProof.siblings)

            // If the obtained root is equal to the proof root, then the proof is valid.
            return root === merkleProof.root
        }

        // If there is a matching entry the proof is definitely a non-membership
        // proof. In this case it checks if the matching node belongs to the tree
        // and then it checks if the number of the first matching bits of the keys
        // is greater than or equal to the number of the siblings.
        const matchingPath = keyToPath(merkleProof.matchingEntry[0])
        const node = this.hash(merkleProof.matchingEntry)
        const root = this.calculateRoot(node, matchingPath, merkleProof.siblings)

        if (root === merkleProof.root) {
            const path = keyToPath(merkleProof.entry[0])
            // Returns the first common bits of the two keys: the
            // non-member key and the matching key.
            const firstMatchingBits = getFirstCommonElements(path, matchingPath)
            // If the non-member key was a key of a tree entry, the depth of the
            // matching node should be greater than the number of the first common
            // bits of the keys. The depth of a node can be defined by the number
            // of its siblings.
            return merkleProof.siblings.length <= firstMatchingBits.length
        }

        return false
    }

    /**
     * Searches for an entry in the tree. If the key passed as parameter exists in
     * the tree, the function returns the entry, otherwise it returns the entry
     * with only the key, and when there is another existing entry
     * in the same path it returns also this entry as 'matching entry'.
     * In any case the function returns the siblings of the path.
     * @param key The key of the entry to search for.
     * @returns The entry response.
     */
    private retrieveEntry(key: Key): EntryResponse {
        const path = keyToPath(key)
        const siblings: Siblings = []

        // Starts from the root and goes down into the tree until it finds
        // the entry, a zero node or a matching entry.
        for (let i = 0, node = this.root; node !== this.zeroNode; i += 1) {
            const childNodes = this.nodes.get(node) as ChildNodes
            const direction = path[i]

            // If the third position of the array is not empty the child nodes
            // are an entry of the tree.
            if (childNodes[2] !== undefined) {
                if (childNodes[0] === key) {
                    // An entry with the same key was found and
                    // it returns it with the siblings.
                    return { entry: childNodes, siblings }
                }
                // The entry found does not have the same key. But the key of this
                // particular entry matches the first 'i' bits of the key passed
                // as parameter and it can be useful in several functions.
                return { entry: [key], matchingEntry: childNodes, siblings }
            }

            // When it goes down into the tree and follows the path, in every step
            // a node is chosen between the left and the right child nodes, and the
            // opposite node is saved as siblings.
            node = childNodes[direction] as Node
            siblings.push(childNodes[Number(!direction)] as Node)
        }

        // The path led to a zero node.
        return { entry: [key], siblings }
    }

    /**
     * Calculates nodes with a bottom-up approach until it reaches the root node.
     * @param node The node to start from.
     * @param path The path of the key.
     * @param siblings The siblings of the path.
     * @returns The root node.
     */
    private calculateRoot(node: Node, path: number[], siblings: Siblings): Node {
        for (let i = siblings.length - 1; i >= 0; i -= 1) {
            const childNodes: ChildNodes = path[i] ? [siblings[i], node] : [node, siblings[i]]
            node = this.hash(childNodes)
        }

        return node
    }

    /**
     * Adds new nodes in the tree with a bottom-up approach until it reaches the root node.
     * @param node The node to start from.
     * @param path The path of the key.
     * @param siblings The siblings of the path.
     * @param i The index to start from.
     * @returns The root node.
     */
    private addNewNodes(node: Node, path: number[], siblings: Siblings, i = siblings.length - 1): Node {
        for (; i >= 0; i -= 1) {
            const childNodes: ChildNodes = path[i] ? [siblings[i], node] : [node, siblings[i]]
            node = this.hash(childNodes)

            this.nodes.set(node, childNodes)
        }

        return node
    }

    /**
     * Deletes nodes in the tree with a bottom-up approach until it reaches the root node.
     * @param node The node to start from.
     * @param path The path of the key.
     * @param siblings The siblings of the path.
     */
    private deleteOldNodes(node: Node, path: number[], siblings: Siblings) {
        for (let i = siblings.length - 1; i >= 0; i -= 1) {
            const childNodes: ChildNodes = path[i] ? [siblings[i], node] : [node, siblings[i]]
            node = this.hash(childNodes)

            this.nodes.delete(node)
        }
    }

    /**
     * Checks if a node is a leaf node.
     * @param node A node of the tree.
     * @returns True if the node is a leaf, false otherwise.
     */
    private isLeaf(node: Node): boolean {
        const childNodes = this.nodes.get(node)

        return !!(childNodes && childNodes[2])
    }

    /**
     * Checks the parameter type.
     * @param parameter The parameter to check.
     */
    private checkParameterType(parameter: Key | Value) {
        if (this.bigNumbers && typeof parameter !== "bigint") {
            throw new Error(`Parameter ${parameter} must be a big number`)
        }

        if (!this.bigNumbers && !checkHex(parameter as string)) {
            throw new Error(`Parameter ${parameter} must be a hexadecimal`)
        }
    }
}
