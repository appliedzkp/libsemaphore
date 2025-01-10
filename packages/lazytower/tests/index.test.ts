import { poseidon2 } from "poseidon-lite"
import { LazyTowerHashChainProofBuilder } from "../src"

const hash = (a: bigint, b: bigint): bigint => poseidon2([a, b])

describe("LazyTowerHashChainProofBuilder", () => {
    it("Should build a proof", () => {
        const pb = LazyTowerHashChainProofBuilder(3, 3)
        for (let i = BigInt(0); i < 11; i += BigInt(1)) {
            pb.add(i)
        }
        const index = pb.indexOf(BigInt(4))
        const proof = pb.build(index)

        const h = (a: number | bigint, b: number | bigint) => hash(BigInt(a), BigInt(b))

        // 012 345 678
        // 9   10
        const L = []
        L[2] = []
        L[1] = [h(h(0, 1), 2), h(h(3, 4), 5), h(h(6, 7), 8)]
        L[0] = [9, 10]

        const D = []
        D[2] = 0
        D[1] = h(h(L[1][0], L[1][1]), L[1][2])
        D[0] = h(L[0][0], L[0][1])

        const ans = {
            levelLengths: BigInt(0x32),
            digestOfDigests: h(D[1], D[0]), // top-down
            topDownDigests: [D[1], D[0], BigInt(0)], // top-down and zero padding
            rootLv: 1,
            rootLevel: L[1],
            childrens: [
                [BigInt(3), BigInt(4), BigInt(5)],
                [BigInt(0), BigInt(0), BigInt(0)] // rootLv here
                // only H - 1 levels
            ],
            item: BigInt(4)
        }
        expect(proof).toEqual(ans)
    })

    it("Should build a proof 2", () => {
        const pb = LazyTowerHashChainProofBuilder(10, 4, hash)
        for (let i = BigInt(0); i < 150; i += BigInt(1)) {
            pb.add(i)
        }
        const index = pb.indexOf(BigInt(42))
        const proof = pb.build(index)

        // console.log(proof) and replace (\d+)n with BigInt("$1")
        const ans = {
            levelLengths: BigInt("8466"),
            digestOfDigests: BigInt("19260615748091768530426964318883829655407684674262674118201416393073357631548"),
            topDownDigests: [
                BigInt("11606235313340788975553986881206148975708550071371494991713397040288897077102"),
                BigInt("18495397265763935736123111771752209927150052777598404957994272011704245682779"),
                BigInt("18801712394745483811033456933953954791894699812924877968490149877093764724813"),
                BigInt("7484852499570635450337779587061833141700590058395918107227385307780465498841"),
                BigInt("0"),
                BigInt("0"),
                BigInt("0"),
                BigInt("0"),
                BigInt("0"),
                BigInt("0")
            ],
            rootLv: 3,
            rootLevel: [
                BigInt("11507854663063665480309728235359892842291004579924997465688869513541015477560"),
                BigInt("11037030444574900797927005338519516919270534249701967933846186493839909577965"),
                BigInt("0"),
                BigInt("0")
            ],
            childrens: [
                [BigInt("40"), BigInt("41"), BigInt("42"), BigInt("43")],
                [
                    BigInt("11944715634172716889863833477757954683469703345994102228733316916746229590999"),
                    BigInt("19851208805805724794666644403689912135758363396527173684750001916183505998349"),
                    BigInt("16627065259441779253298501707804847793972993984539762474803049564228403633626"),
                    BigInt("5478180431823836570443558534637355585513693982262372570670354340883095675715")
                ],
                [
                    BigInt("11752403934261483187058729336868403966142816960200339934976676637743922078923"),
                    BigInt("14851192898657621494195354827105887579565352937114147589740649302886557270892"),
                    BigInt("2957022710546827627567236675225732592793222602156879882669535324527316862435"),
                    BigInt("12484807722681449517362079078090869962809809197179200337956274588459792763496")
                ],
                [BigInt("0"), BigInt("0"), BigInt("0"), BigInt("0")],
                [BigInt("0"), BigInt("0"), BigInt("0"), BigInt("0")],
                [BigInt("0"), BigInt("0"), BigInt("0"), BigInt("0")],
                [BigInt("0"), BigInt("0"), BigInt("0"), BigInt("0")],
                [BigInt("0"), BigInt("0"), BigInt("0"), BigInt("0")],
                [BigInt("0"), BigInt("0"), BigInt("0"), BigInt("0")]
                // only H - 1 levels
            ],
            item: BigInt("42")
        }
        expect(proof).toEqual(ans)
    })

    it("Should work with the default hash function.", () => {
        const pb = LazyTowerHashChainProofBuilder(2, 3, hash)
        for (let i = BigInt(0); i < 12; i += BigInt(1)) {
            pb.add(i)
        }
        const pbDefaultHash = LazyTowerHashChainProofBuilder(2, 3)
        for (let i = BigInt(0); i < 12; i += BigInt(1)) {
            pbDefaultHash.add(i)
        }
        expect(pb.build(11)).toEqual(pbDefaultHash.build(11))
    })

    it("Should not initialize with wrong parameters", () => {
        const fun1 = () => LazyTowerHashChainProofBuilder(undefined as any, 2, hash)
        expect(fun1).toThrow("Parameter 'H' is not defined")

        const fun2 = () => LazyTowerHashChainProofBuilder(10, 4, 1 as any)
        expect(fun2).toThrow("Parameter 'hash' is none of these types: function")
    })

    it("Should not add an item in a full tower", () => {
        const pb = LazyTowerHashChainProofBuilder(2, 3, hash)
        for (let i = BigInt(0); i < 12; i += BigInt(1)) {
            pb.add(i)
        }
        const fun = () => pb.add(BigInt(12))
        expect(fun).toThrow("The tower is full.")
    })

    it("Should not create a proof with the wrong index", () => {
        const pb = LazyTowerHashChainProofBuilder(10, 4, hash)
        const fun1 = () => pb.build(-1)
        expect(fun1).toThrow("The tower is empty.")
        const fun2 = () => pb.build(0)
        expect(fun2).toThrow("The tower is empty.")

        pb.add(BigInt(0))
        const fun3 = () => pb.build(-1)
        expect(fun3).toThrow("Index out of range: -1")
        pb.build(0) // now OK
        const fun4 = () => pb.build(1)
        expect(fun4).toThrow("Index out of range: 1")
    })
})
