use std::str::FromStr;

use num_bigint::BigInt;

use super::{element::Element, hash_to_field};
use crate::test_utils::TestCase;

struct Point {
    x: &'static str,
    y: &'static str,
}

struct EncodePayload {
    msg:   &'static [u8],
    point: Point,
    q:     Point,
}

static ENCODE_TEST_DST: &[u8] = b"QUUX-V01-CS02-with-BN254G1_XMD:SHA-256_SVDW_NU_".as_slice();
fn encode_test_vector() -> Vec<TestCase<EncodePayload, Element>> {
    vec![
        TestCase {
            name:     "empty string",
            payload:  EncodePayload {
                msg:   b"".as_slice(),
                point: Point {
                    x: "0x1bb8810e2ceaf04786d4efd216fc2820ddd9363712efc736ada11049d8af5925",
                    y: "0x1efbf8d54c60d865cce08437668ea30f5bf90d287dbd9b5af31da852915e8f11",
                },
                q:     Point {
                    x: "0x1bb8810e2ceaf04786d4efd216fc2820ddd9363712efc736ada11049d8af5925",
                    y: "0x1efbf8d54c60d865cce08437668ea30f5bf90d287dbd9b5af31da852915e8f11",
                },
            },
            criteria: Element::from_big_hex_str(b"cb81538a98a2e3580076eed495256611813f6dae9e16d3d4f8de7af0e9833e1"),
        },
        TestCase {
            name:     "very short string",
            payload:  EncodePayload {
                msg:   b"abc".as_slice(),
                point: Point {
                    x: "0xda4a96147df1f35b0f820bd35c6fac3b80e8e320de7c536b1e054667b22c332",
                    y: "0x189bd3fbffe4c8740d6543754d95c790e44cd2d162858e3b733d2b8387983bb7",
                },
                q:     Point {
                    x: "0xda4a96147df1f35b0f820bd35c6fac3b80e8e320de7c536b1e054667b22c332",
                    y: "0x189bd3fbffe4c8740d6543754d95c790e44cd2d162858e3b733d2b8387983bb7",
                },
            },
            criteria: Element::from_big_hex_str(b"ba35e127276e9000b33011860904ddee28f1d48ddd3577e2a797ef4a5e62319"),
        },
        TestCase {
            name:     "short string",
            payload:  EncodePayload {
                msg:   b"abcdef0123456789".as_slice(),
                point: Point {
                    x: "0x2ff727cfaaadb3acab713fa22d91f5fddab3ed77948f3ef6233d7ea9b03f4da1",
                    y: "0x304080768fd2f87a852155b727f97db84b191e41970506f0326ed4046d1141aa",
                },
                q:     Point {
                    x: "0x2ff727cfaaadb3acab713fa22d91f5fddab3ed77948f3ef6233d7ea9b03f4da1",
                    y: "0x304080768fd2f87a852155b727f97db84b191e41970506f0326ed4046d1141aa",
                },
            },
            criteria: Element::from_big_hex_str(b"11852286660cd970e9d7f46f99c7cca2b75554245e91b9b19d537aa6147c28fc"),
        },
        TestCase {
            name:     "long string",
            payload:  EncodePayload {
                msg:   b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq".as_slice(),
                point: Point {
                    x: "0x11a2eaa8e3e89de056d1b3a288a7f733c8a1282efa41d28e71af065ab245df9b",
                    y: "0x60f37c447ac29fd97b9bb83be98ddccf15e34831a9cdf5493b7fede0777ae06",
                },
                q:     Point {
                    x: "0x11a2eaa8e3e89de056d1b3a288a7f733c8a1282efa41d28e71af065ab245df9b",
                    y: "0x60f37c447ac29fd97b9bb83be98ddccf15e34831a9cdf5493b7fede0777ae06",
                },
            },
            criteria: Element::from_big_hex_str(b"174d1c85d8a690a876cc1deba0166d30569fafdb49cb3ed28405bd1c5357a1cc"),
        },
        TestCase {
            name:     "really long string",
            payload:  EncodePayload {
                msg:   b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".as_slice(),
                point: Point {
                    x: "0x27409dccc6ee4ce90e24744fda8d72c0bc64e79766f778da0c1c0ef1c186ea84",
                    y: "0x1ac201a542feca15e77f30370da183514dc99d8a0b2c136d64ede35cd0b51dc0",
                },
                q:     Point {
                    x: "0x27409dccc6ee4ce90e24744fda8d72c0bc64e79766f778da0c1c0ef1c186ea84",
                    y: "0x1ac201a542feca15e77f30370da183514dc99d8a0b2c136d64ede35cd0b51dc0",
                },
            },
            criteria: Element::from_big_hex_str(b"73b81432b4cf3a8a9076201500d1b94159539f052a6e0928db7f2df74bff672"),
        },
    ]
}

struct HashPayload {
    msg:   &'static [u8],
    point: Point,
    q0:    Point,
    q1:    Point,
}

#[derive(Debug, PartialEq, Eq)]
struct HashCriteria {
    u0: Element,
    u1: Element,
}

static HASH_TEST_DST: &[u8] = b"QUUX-V01-CS02-with-BN254G1_XMD:SHA-256_SVDW_RO_".as_slice();
fn hash_test_vector() -> Vec<TestCase<HashPayload, HashCriteria>> {
    vec![
        TestCase {
            name:     "empty string",
            payload:  HashPayload {
                msg:   b"".as_slice(),
                point: Point {
                    x: "0xa976ab906170db1f9638d376514dbf8c42aef256a54bbd48521f20749e59e86",
                    y: "0x2925ead66b9e68bfc309b014398640ab55f6619ab59bc1fab2210ad4c4d53d5",
                },
                q0:     Point {
                    x: "0xe449b959abbd0e5ab4c873eaeb1ccd887f1d9ad6cd671fd72cb8d77fb651892",
                    y: "0x29ff1e36867c60374695ee0c298fcbef2af16f8f97ed356fa75e61a797ebb265",
                },
                q1:     Point {
                    x: "0x19388d9112a306fba595c3a8c63daa8f04205ad9581f7cf105c63c442d7c6511",
                    y: "0x182da356478aa7776d1de8377a18b41e933036d0b71ab03f17114e4e673ad6e4",
                },
                
            },
            criteria: HashCriteria {
                u0: Element::from_big_hex_str(b"2f87b81d9d6ef05ad4d249737498cc27e1bd485dca804487844feb3c67c1a9b5"),
                u1: Element::from_big_hex_str(b"6de2d0d7c0d9c7a5a6c0b74675e7543f5b98186b5dbf831067449000b2b1f8e"),
            },
        },
        TestCase {
            name:     "very short string",
            payload:  HashPayload {
                msg:   b"abc".as_slice(),
                point: Point {
                    x: "0x23f717bee89b1003957139f193e6be7da1df5f1374b26a4643b0378b5baf53d1",
                    y: "0x4142f826b71ee574452dbc47e05bc3e1a647478403a7ba38b7b93948f4e151d",
                },
                q0:     Point {
                    x: "0x1452c8cc24f8dedc25b24d89b87b64e25488191cecc78464fea84077dd156f8d",
                    y: "0x209c3633505ba956f5ce4d974a868db972b8f1b69d63c218d360996bcec1ad41",
                },
                q1:     Point {
                    x: "0x4e8357c98524e6208ae2b771e370f0c449e839003988c2e4ce1eaf8d632559f",
                    y: "0x4396ec43dd8ec8f2b4a705090b5892219759da30154c39490fc4d59d51bb817",
                },
            },
            criteria: HashCriteria {
                u0: Element::from_big_hex_str(b"11945105b5e3d3b9392b5a2318409cbc28b7246aa47fa30da5739907737799a9"),
                u1: Element::from_big_hex_str(b"1255fc9ad5a6e0fb440916f091229bda611c41be2f2283c3d8f98c596be4c8c9"),
            },
        },
        TestCase {
            name:     "short string",
            payload:  HashPayload {
                msg:   b"abcdef0123456789".as_slice(),
                point: Point {
                    x: "0x187dbf1c3c89aceceef254d6548d7163fdfa43084145f92c4c91c85c21442d4a",
                    y: "0xabd99d5b0000910b56058f9cc3b0ab0a22d47cf27615f588924fac1e5c63b4d",
                },
                q0:     Point {
                    x: "0x28d01790d2a1cc4832296774438acd46c2ce162d03099926478cf52319daba8d",
                    y: "0x10227ab2707fd65fb45e87f0a48cfe3556f04113d27b1da9a7ae1709007355e1",
                },
                q1:     Point {
                    x: "0x7dc256c7aadac1b4e1d23b3b2bbb5e2ffd9c753b9073d8d952ead8f812ce1b3",
                    y: "0x2589008b2e15dcb3d16cdc1fed2634778001b1b28f0ab433f4f5ec6635c55e1e",
                },
            },
            criteria: HashCriteria {
                u0: Element::from_big_hex_str(b"2f7993a6b43a8dbb37060e790011a888157f456b895b925c3568690685f4983d"),
                u1: Element::from_big_hex_str(b"2677d0532b47a4cead2488845e7df7ebc16c0b8a2cd8a6b7f4ce99f51659794e"),
            },
        },
        TestCase {
            name:     "long string",
            payload:  HashPayload {
                msg:   b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq".as_slice(),
                point: Point {
                    x: "0xfe2b0743575324fc452d590d217390ad48e5a16cf051bee5c40a2eba233f5c",
                    y: "0x794211e0cc72d3cbbdf8e4e5cd6e7d7e78d101ff94862caae8acbe63e9fdc78",
                },
                q0:     Point {
                    x: "0x1c53b05f2fce15ba0b9100650c0fb46de1fb62f1d0968b69151151bd25dfefa4",
                    y: "0x1fe783faf4bdbd79b717784dc59619106e4acccfe3b5d9750799729d855e7b81",
                },
                q1:     Point {
                    x: "0x214a4e6e97adda47558f80088460eabd71ed35bc8ceafb99a493dd6f4e2b3f0a",
                    y: "0xfaaeb29cc23f9d09b187a99741613aed84443e7c35736258f57982d336d13bd",
                },
            },
            criteria: HashCriteria {
                u0: Element::from_big_hex_str(b"2a50be15282ee276b76db1dab761f75401cdc8bd9fff81fcf4d428db16092a7b"),
                u1: Element::from_big_hex_str(b"23b41953676183c30aca54b5c8bd3ffe3535a6238c39f6b15487a5467d5d20eb"),
            },
        },
        TestCase {
            name:     "really long string",
            payload:  HashPayload {
                msg:   b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".as_slice(),
                point: Point {
                    x: "0x2298ba379768da62495af6bb390ffca9156fde1dc167235b89c6dd008d2f2f3b",
                    y: "0x660564cf6fce5cdea4780f5976dd0932559336fd072b4ddd83ec37f00fc7699",
                },
                q0:     Point {
                    x: "0x2298ba379768da62495af6bb390ffca9156fde1dc167235b89c6dd008d2f2f3b",
                    y: "0x660564cf6fce5cdea4780f5976dd0932559336fd072b4ddd83ec37f00fc7699",
                },
                q1:     Point {
                    x: "0x2811dea430f7a1f6c8c941ecdf0e1e725b8ad1801ad15e832654bd8f10b62f16",
                    y: "0x253390ed4fb39e58c30ca43892ab0428684cfb30b9df05fc239ab532eaa02444",
                },
            },
            criteria: HashCriteria {
                u0: Element::from_big_hex_str(b"48527470f534978bae262c0f3ba8380d7f560916af58af9ad7dcb6a4238e633"),
                u1: Element::from_big_hex_str(b"19a6d8be25702820b9b11eada2d42f425343889637a01ecd7672fbcf590d9ffe"),
            },
        },
    ]
}

impl Element {
    fn from_big_hex_str(hex: &[u8]) -> Self {
        let big_int = BigInt::parse_bytes(hex, 16).unwrap();

        Self::from_big_int(big_int)
    }
}

#[test]
fn test_encode_vector() {
    TestCase::run_output_match(encode_test_vector(), |p| {
        let elements = hash_to_field::<sha2::Sha256>(p.msg, ENCODE_TEST_DST, 1).unwrap();
        elements[0]
    });
}

#[test]
fn test_hash_vector() {
    TestCase::run_output_match(hash_test_vector(), |p| {
        let elements = hash_to_field::<sha2::Sha256>(p.msg, HASH_TEST_DST, 2).unwrap();
        HashCriteria {
            u0: elements[0],
            u1: elements[1],
        }
    });
}
