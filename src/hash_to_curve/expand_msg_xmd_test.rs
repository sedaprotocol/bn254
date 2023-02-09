use super::*;

struct XmdTestCase {
    msg:          &'static [u8],
    len_in_bytes: usize,
}

#[test]
fn test_xmd_msg_expand_sha256() {
    let dst = b"QUUX-V01-CS02-with-expander-SHA256-128";

    let tests = vec![
        TestCase {
            name:     "empty msg 32 bytes",
            payload:  XmdTestCase {
                msg: b"".as_slice(),
                len_in_bytes: 0x20,
            },
            criteria: hex::decode(b"68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235").unwrap(),
        },
        TestCase {
            name:     "very short msg 32 bytes",
            payload:  XmdTestCase {
                msg: b"abc".as_slice(),
                len_in_bytes: 0x20,
            },
            criteria: hex::decode(b"d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615").unwrap(),
        },
        TestCase {
            name:     "short msg 32 bytes",
            payload:  XmdTestCase {
                msg: b"abcdef0123456789".as_slice(),
                len_in_bytes: 0x20,
            },
            criteria: hex::decode(b"eff31487c770a893cfb36f912fbfcbff40d5661771ca4b2cb4eafe524333f5c1").unwrap(),
        },
        TestCase {
            name:     "long msg 32 bytes",
            payload:  XmdTestCase {
                msg: b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq".as_slice(),
                len_in_bytes: 0x20
            },
            criteria: hex::decode(b"b23a1d2b4d97b2ef7785562a7e8bac7eed54ed6e97e29aa51bfe3f12ddad1ff9").unwrap(),
        },
        TestCase {
            name:     "very long msg 32 bytes",
            payload:  XmdTestCase {
                msg: b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".as_slice(),
                len_in_bytes: 0x20,
            },
            criteria: hex::decode(b"4623227bcc01293b8c130bf771da8c298dede7383243dc0993d2d94823958c4c").unwrap(),
        },
        TestCase {
            name:     "empty msg 128 bytes",
            payload:  XmdTestCase {
                msg: b"".as_slice(),
                len_in_bytes: 0x80,
            },
            criteria: hex::decode(b"af84c27ccfd45d41914fdff5df25293e221afc53d8ad2ac06d5e3e29485dadbee0d121587713a3e0dd4d5e69e93eb7cd4f5df4cd103e188cf60cb02edc3edf18eda8576c412b18ffb658e3dd6ec849469b979d444cf7b26911a08e63cf31f9dcc541708d3491184472c2c29bb749d4286b004ceb5ee6b9a7fa5b646c993f0ced").unwrap(),
        },
        TestCase {
            name:     "very short msg 128 bytes",
            payload:  XmdTestCase {
                msg: b"abc".as_slice(),
                len_in_bytes: 0x80,
            },
            criteria: hex::decode(b"abba86a6129e366fc877aab32fc4ffc70120d8996c88aee2fe4b32d6c7b6437a647e6c3163d40b76a73cf6a5674ef1d890f95b664ee0afa5359a5c4e07985635bbecbac65d747d3d2da7ec2b8221b17b0ca9dc8a1ac1c07ea6a1e60583e2cb00058e77b7b72a298425cd1b941ad4ec65e8afc50303a22c0f99b0509b4c895f40").unwrap(),
        },
        TestCase {
            name:     "short msg 128 bytes",
            payload:  XmdTestCase {
                msg: b"abcdef0123456789".as_slice(),
                len_in_bytes: 0x80,
            },
            criteria: hex::decode(b"ef904a29bffc4cf9ee82832451c946ac3c8f8058ae97d8d629831a74c6572bd9ebd0df635cd1f208e2038e760c4994984ce73f0d55ea9f22af83ba4734569d4bc95e18350f740c07eef653cbb9f87910d833751825f0ebefa1abe5420bb52be14cf489b37fe1a72f7de2d10be453b2c9d9eb20c7e3f6edc5a60629178d9478df").unwrap(),
        },
        TestCase {
            name:     "long msg 128 bytes",
            payload:  XmdTestCase {
                msg: b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq".as_slice(),
                len_in_bytes: 0x80
            },
            criteria: hex::decode(b"80be107d0884f0d881bb460322f0443d38bd222db8bd0b0a5312a6fedb49c1bbd88fd75d8b9a09486c60123dfa1d73c1cc3169761b17476d3c6b7cbbd727acd0e2c942f4dd96ae3da5de368d26b32286e32de7e5a8cb2949f866a0b80c58116b29fa7fabb3ea7d520ee603e0c25bcaf0b9a5e92ec6a1fe4e0391d1cdbce8c68a").unwrap(),
        },
        TestCase {
            name:     "very long msg 128 bytes",
            payload:  XmdTestCase {
                msg: b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".as_slice(),
                len_in_bytes: 0x80,
            },
            criteria: hex::decode(b"546aff5444b5b79aa6148bd81728704c32decb73a3ba76e9e75885cad9def1d06d6792f8a7d12794e90efed817d96920d728896a4510864370c207f99bd4a608ea121700ef01ed879745ee3e4ceef777eda6d9e5e38b90c86ea6fb0b36504ba4a45d22e86f6db5dd43d98a294bebb9125d5b794e9d2a81181066eb954966a487").unwrap(),
        },
    ];

    TestCase::run_output_match(tests, |p| {
        expand_msg_xmd::<sha2::Sha256>(p.msg, dst, p.len_in_bytes).unwrap()
    });
}

#[test]
fn test_xmd_msg_expand_sha512() {
    let dst = b"QUUX-V01-CS02-with-expander-SHA512-256";

    let tests = vec![
        TestCase {
            name:     "empty msg 32 bytes",
            payload:  XmdTestCase {
                msg: b"".as_slice(),
                len_in_bytes: 0x20,
            },
            criteria: hex::decode(b"6b9a7312411d92f921c6f68ca0b6380730a1a4d982c507211a90964c394179ba").unwrap(),
        },
        TestCase {
            name:     "very short msg 32 bytes",
            payload:  XmdTestCase {
                msg: b"abc".as_slice(),
                len_in_bytes: 0x20,
            },
            criteria: hex::decode(b"0da749f12fbe5483eb066a5f595055679b976e93abe9be6f0f6318bce7aca8dc").unwrap(),
        },
        TestCase {
            name:     "short msg 32 bytes",
            payload:  XmdTestCase {
                msg: b"abcdef0123456789".as_slice(),
                len_in_bytes: 0x20,
            },
            criteria: hex::decode(b"087e45a86e2939ee8b91100af1583c4938e0f5fc6c9db4b107b83346bc967f58").unwrap(),
        },
        TestCase {
            name:     "long msg 32 bytes",
            payload:  XmdTestCase {
                msg: b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq".as_slice(),
                len_in_bytes: 0x20
            },
            criteria: hex::decode(b"7336234ee9983902440f6bc35b348352013becd88938d2afec44311caf8356b3").unwrap(),
        },
        TestCase {
            name:     "very long msg 32 bytes",
            payload:  XmdTestCase {
                msg: b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".as_slice(),
                len_in_bytes: 0x20,
            },
            criteria: hex::decode(b"57b5f7e766d5be68a6bfe1768e3c2b7f1228b3e4b3134956dd73a59b954c66f4").unwrap(),
        },
        TestCase {
            name:     "empty msg 128 bytes",
            payload:  XmdTestCase {
                msg: b"".as_slice(),
                len_in_bytes: 0x80,
            },
            criteria: hex::decode(b"41b037d1734a5f8df225dd8c7de38f851efdb45c372887be655212d07251b921b052b62eaed99b46f72f2ef4cc96bfaf254ebbbec091e1a3b9e4fb5e5b619d2e0c5414800a1d882b62bb5cd1778f098b8eb6cb399d5d9d18f5d5842cf5d13d7eb00a7cff859b605da678b318bd0e65ebff70bec88c753b159a805d2c89c55961").unwrap(),
        },
        TestCase {
            name:     "very short msg 128 bytes",
            payload:  XmdTestCase {
                msg: b"abc".as_slice(),
                len_in_bytes: 0x80,
            },
            criteria: hex::decode(b"7f1dddd13c08b543f2e2037b14cefb255b44c83cc397c1786d975653e36a6b11bdd7732d8b38adb4a0edc26a0cef4bb45217135456e58fbca1703cd6032cb1347ee720b87972d63fbf232587043ed2901bce7f22610c0419751c065922b488431851041310ad659e4b23520e1772ab29dcdeb2002222a363f0c2b1c972b3efe1").unwrap(),
        },
        TestCase {
            name:     "short msg 128 bytes",
            payload:  XmdTestCase {
                msg: b"abcdef0123456789".as_slice(),
                len_in_bytes: 0x80,
            },
            criteria: hex::decode(b"3f721f208e6199fe903545abc26c837ce59ac6fa45733f1baaf0222f8b7acb0424814fcb5eecf6c1d38f06e9d0a6ccfbf85ae612ab8735dfdf9ce84c372a77c8f9e1c1e952c3a61b7567dd0693016af51d2745822663d0c2367e3f4f0bed827feecc2aaf98c949b5ed0d35c3f1023d64ad1407924288d366ea159f46287e61ac").unwrap(),
        },
        TestCase {
            name:     "long msg 128 bytes",
            payload:  XmdTestCase {
                msg: b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq".as_slice(),
                len_in_bytes: 0x80
            },
            criteria: hex::decode(b"b799b045a58c8d2b4334cf54b78260b45eec544f9f2fb5bd12fb603eaee70db7317bf807c406e26373922b7b8920fa29142703dd52bdf280084fb7ef69da78afdf80b3586395b433dc66cde048a258e476a561e9deba7060af40adf30c64249ca7ddea79806ee5beb9a1422949471d267b21bc88e688e4014087a0b592b695ed").unwrap(),
        },
        TestCase {
            name:     "very long msg 128 bytes",
            payload:  XmdTestCase {
                msg: b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".as_slice(),
                len_in_bytes: 0x80,
            },
            criteria: hex::decode(b"05b0bfef265dcee87654372777b7c44177e2ae4c13a27f103340d9cd11c86cb2426ffcad5bd964080c2aee97f03be1ca18e30a1f14e27bc11ebbd650f305269cc9fb1db08bf90bfc79b42a952b46daf810359e7bc36452684784a64952c343c52e5124cd1f71d474d5197fefc571a92929c9084ffe1112cf5eea5192ebff330b").unwrap(),
        },
    ];

    TestCase::run_output_match(tests, |p| {
        expand_msg_xmd::<sha2::Sha512>(p.msg, dst, p.len_in_bytes).unwrap()
    });
}
