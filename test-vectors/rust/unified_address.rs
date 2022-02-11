        struct TestVector {
            p2pkh_bytes: Option<[u8; 20]>,
            p2sh_bytes: Option<[u8; 20]>,
            sapling_raw_addr: Option<[u8; 43]>,
            orchard_raw_addr: Option<[u8; 43]>,
            unknown_typecode: u32,
            unknown_bytes: Option<Vec<u8>>,
            unified_addr: Vec<u8>,
            account: u32,
            diversifier_index: u32,
        };

        // From https://github.com/zcash-hackworks/zcash-test-vectors/blob/master/unified_address.py
        let test_vectors = vec![
            TestVector {
                p2pkh_bytes: Some([
                    0xed, 0x95, 0xcf, 0xb2, 0xc6, 0x06, 0x9e, 0xb2, 0x40, 0xa9, 0x8c, 0x00, 0xe2, 0x3b, 0xa2, 0x49, 0x76, 0xcb, 0xd5, 0xc4
                ]),
                p2sh_bytes: None,
                sapling_raw_addr: None,
                orchard_raw_addr: Some([
                    0xd4, 0x71, 0x4e, 0xe7, 0x61, 0xd1, 0xae, 0x82, 0x3b, 0x69, 0x72, 0x15, 0x2e, 0x20, 0x95, 0x7f, 0xef, 0xa3, 0xf6, 0xe3, 0x12, 0x9e, 0xa4, 0xdf, 0xb0, 0xa9, 0xe9, 0x87, 0x03, 0xa6, 0x3d, 0xab, 0x92, 0x95, 0x89, 0xd6, 0xdc, 0x51, 0xc9, 0x70, 0xf9, 0x35, 0xb3
                ]),
                unknown_typecode: 65533,
                unknown_bytes: Some(vec![
                    0xf6, 0xee, 0x69, 0x21, 0x48, 0x1c, 0xdd, 0x86, 0xb3, 0xcc, 0x43, 0x18, 0xd9, 0x61, 0x4f, 0xc8, 0x20, 0x90, 0x5d, 0x04, 0x2b, 0xb1, 0xef, 0x9c, 0xa3, 0xf2, 0x49, 0x88, 0xc7, 0xb3, 0x53, 0x42, 0x01, 0xcf, 0xb1, 0xcd, 0x8d, 0xbf, 0x69, 0xb8, 0x25, 0x0c, 0x18, 0xef, 0x41, 0x29, 0x4c, 0xa9, 0x79, 0x93, 0xdb, 0x54, 0x6c, 0x1f, 0xe0
                ]),
                unified_addr: vec![
                    0x75, 0x31, 0x72, 0x77, 0x64, 0x73, 0x7a, 0x6d, 0x6d, 0x35, 0x7a, 0x6b, 0x73, 0x32, 0x65, 0x35, 0x6a, 0x76, 0x79, 0x79, 0x61, 0x34, 0x67, 0x76, 0x6d, 0x72, 0x36, 0x36, 0x64, 0x70, 0x72, 0x78, 0x70, 0x7a, 0x68, 0x75, 0x73, 0x30, 0x37, 0x38, 0x65, 0x6c, 0x61, 0x7a, 0x72, 0x73, 0x66, 0x77, 0x6d, 0x38, 0x33, 0x6c, 0x72, 0x6b, 0x79, 0x79, 0x64, 0x32, 0x79, 0x74, 0x39, 0x79, 0x6e, 0x32, 0x6d, 0x76, 0x64, 0x78, 0x67, 0x73, 0x6a, 0x65, 0x75, 0x6a, 0x71, 0x6d, 0x65, 0x67, 0x67, 0x63, 0x6c, 0x30, 0x78, 0x7a, 0x38, 0x65, 0x30, 0x67, 0x34, 0x67, 0x79, 0x65, 0x79, 0x30, 0x71, 0x73, 0x6d, 0x76, 0x64, 0x68, 0x78, 0x34, 0x36, 0x75, 0x39, 0x6d, 0x6c, 0x64, 0x77, 0x73, 0x72, 0x75, 0x72, 0x64, 0x34, 0x39, 0x72, 0x74, 0x71, 0x75, 0x37, 0x72, 0x6b, 0x33, 0x74, 0x39, 0x79, 0x34, 0x30, 0x63, 0x70, 0x33, 0x38, 0x6e, 0x32, 0x38, 0x66, 0x34, 0x65, 0x6b, 0x68
                ],
                account: 0,
                diversifier_index: 0,
            },
            TestVector {
                p2pkh_bytes: Some([
                    0xf8, 0x94, 0xcf, 0xc7, 0x03, 0x39, 0x9a, 0xd0, 0x31, 0xe8, 0x74, 0x83, 0xdf, 0x27, 0x65, 0xc4, 0x71, 0x72, 0x3a, 0x97
                ]),
                p2sh_bytes: None,
                sapling_raw_addr: None,
                orchard_raw_addr: Some([
                    0xd8, 0xe5, 0xec, 0xb4, 0xe0, 0x05, 0xc2, 0x87, 0x18, 0xe6, 0x1a, 0x5c, 0x33, 0x6a, 0x4f, 0x36, 0x9e, 0x77, 0x1c, 0xcd, 0xb3, 0x36, 0x3f, 0x4f, 0x7a, 0x04, 0xb0, 0x2a, 0x96, 0x69, 0x01, 0xa4, 0xc0, 0x5d, 0xa6, 0x62, 0xd5, 0xfd, 0x75, 0x67, 0x8f, 0x7f, 0xb4
                ]),
                unknown_typecode: 65530,
                unknown_bytes: None,
                unified_addr: vec![
                    0x75, 0x31, 0x6a, 0x74, 0x32, 0x72, 0x35, 0x30, 0x6a, 0x39, 0x68, 0x34, 0x6b, 0x34, 0x30, 0x70, 0x61, 0x39, 0x39, 0x33, 0x30, 0x66, 0x65, 0x35, 0x66, 0x6e, 0x61, 0x66, 0x36, 0x32, 0x73, 0x73, 0x63, 0x38, 0x78, 0x6e, 0x34, 0x61, 0x68, 0x74, 0x68, 0x72, 0x35, 0x79, 0x72, 0x67, 0x70, 0x37, 0x78, 0x34, 0x68, 0x67, 0x32, 0x6a, 0x39, 0x73, 0x64, 0x7a, 0x74, 0x75, 0x67, 0x77, 0x77, 0x30, 0x76, 0x6d, 0x71, 0x36, 0x74, 0x33, 0x75, 0x74, 0x36, 0x79, 0x6c, 0x67, 0x77, 0x30, 0x35, 0x6a, 0x78, 0x39, 0x7a, 0x61, 0x67, 0x66, 0x35, 0x39, 0x71, 0x65, 0x7a, 0x37, 0x65, 0x72, 0x66, 0x73, 0x34, 0x38, 0x6c, 0x6b, 0x74, 0x76, 0x61, 0x67, 0x61, 0x77, 0x6e, 0x79, 0x35, 0x63, 0x67, 0x74, 0x66, 0x38, 0x6a, 0x70, 0x76, 0x33, 0x72, 0x61, 0x37, 0x65, 0x6b, 0x76, 0x38, 0x61, 0x6c, 0x64, 0x70, 0x30, 0x65, 0x33, 0x78, 0x6c, 0x76, 0x65, 0x70, 0x6a, 0x64, 0x6a, 0x73
                ],
                account: 1,
                diversifier_index: 0,
            },
            TestVector {
                p2pkh_bytes: Some([
                    0xc5, 0x1c, 0xc9, 0x03, 0x02, 0xda, 0xc2, 0x45, 0x82, 0xdf, 0x5b, 0xf5, 0x9e, 0xaf, 0xb1, 0x80, 0xef, 0x7b, 0xbd, 0x26
                ]),
                p2sh_bytes: None,
                sapling_raw_addr: Some([
                    0x88, 0x53, 0x3c, 0x39, 0x8a, 0x49, 0xc2, 0x51, 0x3d, 0xc8, 0x51, 0x62, 0xbf, 0x22, 0x0a, 0xba, 0xf4, 0x7d, 0xc9, 0x83, 0xf1, 0x4e, 0x90, 0x8d, 0xda, 0xaa, 0x73, 0x22, 0xdb, 0xa1, 0x65, 0x31, 0xbc, 0x62, 0xef, 0xe7, 0x50, 0xfe, 0x57, 0x5c, 0x8d, 0x14, 0x9b
                ]),
                orchard_raw_addr: None,
                unknown_typecode: 65530,
                unknown_bytes: None,
                unified_addr: vec![
                    0x75, 0x31, 0x37, 0x6e, 0x67, 0x38, 0x33, 0x75, 0x6e, 0x6b, 0x39, 0x72, 0x6e, 0x77, 0x61, 0x66, 0x7a, 0x73, 0x63, 0x77, 0x7a, 0x38, 0x72, 0x37, 0x6d, 0x39, 0x73, 0x6c, 0x76, 0x39, 0x75, 0x32, 0x67, 0x34, 0x61, 0x70, 0x74, 0x63, 0x6b, 0x6b, 0x6c, 0x30, 0x64, 0x35, 0x64, 0x6b, 0x36, 0x6c, 0x66, 0x7a, 0x74, 0x66, 0x6c, 0x77, 0x68, 0x6c, 0x6a, 0x6e, 0x38, 0x6a, 0x32, 0x6c, 0x72, 0x63, 0x74, 0x32, 0x33, 0x33, 0x78, 0x65, 0x39, 0x6a, 0x61, 0x61, 0x65, 0x64, 0x68, 0x79, 0x6b, 0x6b, 0x64, 0x34, 0x76, 0x37, 0x33, 0x34, 0x66, 0x39, 0x74, 0x32, 0x35, 0x76, 0x30, 0x61, 0x32, 0x75, 0x32, 0x33, 0x7a, 0x73, 0x6c, 0x78, 0x32, 0x38, 0x68, 0x73, 0x61, 0x30, 0x61, 0x67, 0x6c, 0x6c, 0x79, 0x64, 0x7a, 0x75, 0x68, 0x68, 0x7a, 0x37, 0x61, 0x78, 0x71, 0x71, 0x6a, 0x77, 0x64, 0x75, 0x65, 0x38, 0x74, 0x6e, 0x35, 0x61, 0x32, 0x79, 0x32, 0x30, 0x73, 0x72, 0x68
                ],
                account: 2,
                diversifier_index: 0,
            },
            TestVector {
                p2pkh_bytes: None,
                p2sh_bytes: Some([
                    0xa8, 0xd7, 0x55, 0x1d, 0xb5, 0xfd, 0x93, 0x13, 0xe8, 0xc7, 0x20, 0x3d, 0x99, 0x6a, 0xf7, 0xd4, 0x77, 0x08, 0x37, 0x56
                ]),
                sapling_raw_addr: Some([
                    0x52, 0xfd, 0x6a, 0xed, 0xef, 0xbf, 0x40, 0x16, 0x33, 0xc2, 0xe4, 0x53, 0x25, 0x15, 0xeb, 0xcf, 0x95, 0xbc, 0xc2, 0xb4, 0xb8, 0xe4, 0xd6, 0x76, 0xdf, 0xad, 0x7e, 0x17, 0x92, 0x5c, 0x6d, 0xfb, 0x86, 0x71, 0xe5, 0x25, 0x44, 0xdc, 0x2c, 0xa0, 0x75, 0xe2, 0x61
                ]),
                orchard_raw_addr: None,
                unknown_typecode: 65534,
                unknown_bytes: None,
                unified_addr: vec![
                    0x75, 0x31, 0x78, 0x79, 0x79, 0x70, 0x64, 0x6a, 0x30, 0x7a, 0x79, 0x78, 0x63, 0x74, 0x66, 0x66, 0x6b, 0x68, 0x78, 0x79, 0x6d, 0x76, 0x6a, 0x6e, 0x6b, 0x37, 0x6e, 0x38, 0x33, 0x71, 0x66, 0x6c, 0x37, 0x6e, 0x73, 0x65, 0x35, 0x6c, 0x30, 0x71, 0x72, 0x6b, 0x34, 0x6e, 0x32, 0x66, 0x37, 0x64, 0x65, 0x37, 0x6c, 0x37, 0x33, 0x72, 0x7a, 0x79, 0x78, 0x79, 0x70, 0x34, 0x74, 0x63, 0x72, 0x79, 0x75, 0x35, 0x6d, 0x6b, 0x78, 0x75, 0x61, 0x7a, 0x6c, 0x64, 0x6e, 0x63, 0x32, 0x79, 0x30, 0x64, 0x79, 0x74, 0x7a, 0x75, 0x67, 0x79, 0x7a, 0x79, 0x63, 0x67, 0x39, 0x37, 0x30, 0x34, 0x61, 0x6a, 0x66, 0x78, 0x61, 0x73, 0x37, 0x6b, 0x63, 0x75, 0x77, 0x61, 0x77, 0x6d, 0x70, 0x68, 0x77, 0x77, 0x6e, 0x38, 0x38, 0x39, 0x74, 0x39, 0x38, 0x74, 0x37, 0x35, 0x37, 0x65, 0x79, 0x71, 0x66, 0x67, 0x34, 0x6a, 0x76, 0x65, 0x66, 0x74, 0x6b, 0x68, 0x76, 0x72, 0x33, 0x71, 0x67
                ],
                account: 3,
                diversifier_index: 0,
            },
            TestVector {
                p2pkh_bytes: None,
                p2sh_bytes: Some([
                    0xf4, 0x4a, 0xb0, 0x23, 0x75, 0x2c, 0xb5, 0xb4, 0x06, 0xed, 0x89, 0x85, 0xe1, 0x81, 0x30, 0xab, 0x33, 0x36, 0x26, 0x97
                ]),
                sapling_raw_addr: None,
                orchard_raw_addr: Some([
                    0x16, 0x50, 0x82, 0xde, 0x84, 0xf2, 0xad, 0x72, 0x04, 0x42, 0x6f, 0xfa, 0xfd, 0x6b, 0x6c, 0x7d, 0xe9, 0xca, 0xb6, 0xd2, 0x5c, 0x13, 0x84, 0x6a, 0x17, 0x86, 0x71, 0x52, 0x68, 0xc4, 0x15, 0x94, 0x8d, 0xb7, 0x88, 0xf4, 0xa5, 0xe0, 0xda, 0xa0, 0x3d, 0x69, 0x9e
                ]),
                unknown_typecode: 65533,
                unknown_bytes: None,
                unified_addr: vec![
                    0x75, 0x31, 0x70, 0x6a, 0x33, 0x6c, 0x72, 0x65, 0x6d, 0x6e, 0x71, 0x75, 0x73, 0x73, 0x68, 0x39, 0x38, 0x78, 0x66, 0x71, 0x61, 0x33, 0x6a, 0x66, 0x64, 0x70, 0x77, 0x30, 0x38, 0x72, 0x72, 0x6b, 0x35, 0x37, 0x73, 0x30, 0x34, 0x6b, 0x6c, 0x32, 0x36, 0x68, 0x65, 0x70, 0x7a, 0x71, 0x33, 0x74, 0x6a, 0x72, 0x73, 0x6e, 0x78, 0x65, 0x35, 0x74, 0x36, 0x73, 0x71, 0x71, 0x65, 0x67, 0x65, 0x39, 0x76, 0x71, 0x6d, 0x77, 0x6c, 0x63, 0x36, 0x6c, 0x78, 0x63, 0x73, 0x74, 0x6e, 0x63, 0x33, 0x30, 0x6e, 0x35, 0x75, 0x35, 0x72, 0x32, 0x77, 0x6b, 0x6b, 0x7a, 0x68, 0x70, 0x39, 0x36, 0x7a, 0x35, 0x64, 0x30, 0x6a, 0x79, 0x75, 0x30, 0x71, 0x61, 0x37, 0x74, 0x6b, 0x68, 0x63, 0x78, 0x36, 0x66, 0x63, 0x38, 0x6a, 0x35, 0x39, 0x6b, 0x61, 0x6b, 0x38, 0x7a, 0x35, 0x63, 0x65, 0x70, 0x36, 0x32, 0x61, 0x71, 0x6d, 0x61, 0x33, 0x6d, 0x36, 0x34, 0x35, 0x66, 0x68, 0x38, 0x63
                ],
                account: 4,
                diversifier_index: 0,
            },
            TestVector {
                p2pkh_bytes: None,
                p2sh_bytes: None,
                sapling_raw_addr: None,
                orchard_raw_addr: Some([
                    0xea, 0x9d, 0xf8, 0x3f, 0xbe, 0xe0, 0x7d, 0x6f, 0x78, 0x95, 0xeb, 0xb2, 0xea, 0x41, 0xec, 0x7c, 0x4b, 0xa6, 0x82, 0xb8, 0x63, 0xe0, 0x69, 0xb4, 0xa4, 0x38, 0xe3, 0x1c, 0x95, 0x71, 0xc8, 0x31, 0x26, 0xc3, 0x05, 0xd7, 0x54, 0x56, 0x41, 0x2a, 0xea, 0xef, 0x1b
                ]),
                unknown_typecode: 65531,
                unknown_bytes: None,
                unified_addr: vec![
                    0x75, 0x31, 0x32, 0x78, 0x75, 0x67, 0x64, 0x39, 0x30, 0x66, 0x6c, 0x72, 0x6b, 0x64, 0x6b, 0x65, 0x75, 0x33, 0x6e, 0x6c, 0x6e, 0x6e, 0x33, 0x75, 0x65, 0x73, 0x6b, 0x79, 0x35, 0x33, 0x70, 0x71, 0x75, 0x35, 0x6d, 0x32, 0x34, 0x79, 0x36, 0x61, 0x70, 0x78, 0x6d, 0x38, 0x38, 0x6d, 0x34, 0x38, 0x76, 0x37, 0x33, 0x37, 0x34, 0x63, 0x6c, 0x73, 0x35, 0x36, 0x7a, 0x70, 0x39, 0x33, 0x6e, 0x61, 0x79, 0x6c, 0x61, 0x78, 0x64, 0x63, 0x68, 0x66, 0x30, 0x71, 0x61, 0x79, 0x66, 0x78, 0x74, 0x72, 0x67, 0x65, 0x30, 0x34, 0x37, 0x6d, 0x39, 0x35, 0x33, 0x71, 0x7a, 0x33, 0x76, 0x32, 0x67, 0x72, 0x34, 0x6c, 0x74, 0x73, 0x72, 0x32, 0x73, 0x6b, 0x33, 0x72
                ],
                account: 5,
                diversifier_index: 0,
            },
            TestVector {
                p2pkh_bytes: None,
                p2sh_bytes: None,
                sapling_raw_addr: None,
                orchard_raw_addr: Some([
                    0x3c, 0x40, 0x24, 0x69, 0x12, 0xb6, 0xef, 0xef, 0xab, 0x9a, 0x55, 0x24, 0x4a, 0xc2, 0xc1, 0x74, 0xe1, 0xa9, 0xf8, 0xc0, 0xbc, 0x0f, 0xd5, 0x26, 0x93, 0x39, 0x63, 0xc6, 0xec, 0xb9, 0xb8, 0x4e, 0xc8, 0xb0, 0xf6, 0xb4, 0x0d, 0xc8, 0x58, 0xfa, 0x23, 0xc7, 0x2b
                ]),
                unknown_typecode: 65530,
                unknown_bytes: None,
                unified_addr: vec![
                    0x75, 0x31, 0x73, 0x70, 0x75, 0x74, 0x67, 0x35, 0x36, 0x67, 0x73, 0x6a, 0x76, 0x32, 0x33, 0x63, 0x74, 0x35, 0x34, 0x6d, 0x72, 0x77, 0x64, 0x6c, 0x61, 0x6e, 0x7a, 0x76, 0x65, 0x71, 0x63, 0x37, 0x74, 0x7a, 0x73, 0x35, 0x6d, 0x78, 0x78, 0x6e, 0x61, 0x61, 0x35, 0x63, 0x64, 0x65, 0x67, 0x6d, 0x30, 0x33, 0x68, 0x67, 0x37, 0x78, 0x36, 0x36, 0x61, 0x79, 0x70, 0x79, 0x64, 0x73, 0x36, 0x35, 0x6d, 0x39, 0x32, 0x76, 0x74, 0x39, 0x75, 0x61, 0x78, 0x6c, 0x36, 0x37, 0x32, 0x73, 0x75, 0x68, 0x70, 0x63, 0x36, 0x7a, 0x37, 0x68, 0x74, 0x77, 0x76, 0x65, 0x70, 0x79, 0x68, 0x6b, 0x72, 0x70, 0x66, 0x75, 0x73, 0x76, 0x61, 0x7a, 0x71, 0x75, 0x65, 0x39
                ],
                account: 6,
                diversifier_index: 0,
            },
            TestVector {
                p2pkh_bytes: None,
                p2sh_bytes: Some([
                    0xde, 0xfa, 0x3d, 0x5a, 0x57, 0xef, 0xc2, 0xe1, 0xe9, 0xb0, 0x1a, 0x03, 0x55, 0x87, 0xd5, 0xfb, 0x1a, 0x38, 0xe0, 0x1d
                ]),
                sapling_raw_addr: None,
                orchard_raw_addr: Some([
                    0xcc, 0x09, 0x9c, 0xc2, 0x14, 0xe5, 0x6b, 0x11, 0x92, 0xc7, 0xb5, 0xb1, 0x7e, 0x95, 0x8c, 0x34, 0x13, 0xe2, 0x7f, 0xef, 0xd5, 0x53, 0x38, 0x07, 0x00, 0xac, 0xa8, 0x1b, 0x24, 0xb2, 0x91, 0x8c, 0xac, 0x95, 0x1a, 0x1a, 0x68, 0x01, 0x7f, 0xac, 0x52, 0x5a, 0x18
                ]),
                unknown_typecode: 65535,
                unknown_bytes: None,
                unified_addr: vec![
                    0x75, 0x31, 0x76, 0x67, 0x73, 0x6b, 0x63, 0x6d, 0x39, 0x39, 0x78, 0x35, 0x67, 0x68, 0x75, 0x61, 0x75, 0x76, 0x68, 0x33, 0x79, 0x78, 0x71, 0x37, 0x77, 0x74, 0x70, 0x37, 0x75, 0x6e, 0x36, 0x61, 0x30, 0x79, 0x36, 0x63, 0x61, 0x79, 0x64, 0x73, 0x6e, 0x6e, 0x33, 0x35, 0x70, 0x32, 0x64, 0x75, 0x77, 0x70, 0x77, 0x73, 0x35, 0x68, 0x73, 0x36, 0x70, 0x79, 0x67, 0x6a, 0x68, 0x77, 0x70, 0x37, 0x38, 0x32, 0x6a, 0x71, 0x6e, 0x65, 0x72, 0x7a, 0x6c, 0x68, 0x78, 0x77, 0x33, 0x70, 0x34, 0x39, 0x71, 0x66, 0x6d, 0x71, 0x32, 0x37, 0x38, 0x33, 0x39, 0x71, 0x6a, 0x74, 0x72, 0x66, 0x79, 0x76, 0x68, 0x6b, 0x37, 0x79, 0x64, 0x39, 0x38, 0x77, 0x39, 0x6e, 0x30, 0x64, 0x36, 0x6a, 0x6e, 0x73, 0x36, 0x75, 0x68, 0x34, 0x66, 0x63, 0x33, 0x68, 0x73, 0x64, 0x66, 0x37, 0x36, 0x36, 0x6b, 0x6e, 0x74, 0x71, 0x6e, 0x6c, 0x6a, 0x64, 0x6b, 0x64, 0x35, 0x36, 0x67, 0x63, 0x6e
                ],
                account: 7,
                diversifier_index: 0,
            },
            TestVector {
                p2pkh_bytes: None,
                p2sh_bytes: None,
                sapling_raw_addr: None,
                orchard_raw_addr: Some([
                    0x5f, 0x09, 0xa9, 0x80, 0x7a, 0x56, 0x32, 0x3b, 0x26, 0x3b, 0x05, 0xdf, 0x36, 0x8d, 0xc2, 0x83, 0x91, 0xb2, 0x1a, 0x64, 0xa0, 0xe1, 0xb4, 0x0f, 0x9a, 0x68, 0x03, 0xb7, 0xe6, 0x8f, 0x39, 0x05, 0x92, 0x3f, 0x35, 0xcb, 0x01, 0xf1, 0x19, 0xb2, 0x23, 0xf4, 0x93
                ]),
                unknown_typecode: 65530,
                unknown_bytes: None,
                unified_addr: vec![
                    0x75, 0x31, 0x63, 0x78, 0x63, 0x63, 0x79, 0x65, 0x6d, 0x6d, 0x30, 0x38, 0x74, 0x79, 0x64, 0x77, 0x6d, 0x74, 0x39, 0x68, 0x70, 0x32, 0x73, 0x35, 0x6e, 0x66, 0x38, 0x77, 0x6a, 0x76, 0x6c, 0x75, 0x75, 0x75, 0x36, 0x6c, 0x32, 0x65, 0x38, 0x61, 0x39, 0x6a, 0x66, 0x6c, 0x6c, 0x64, 0x78, 0x61, 0x73, 0x6e, 0x7a, 0x6b, 0x64, 0x38, 0x66, 0x76, 0x65, 0x72, 0x71, 0x70, 0x63, 0x6a, 0x30, 0x78, 0x6e, 0x76, 0x72, 0x61, 0x63, 0x7a, 0x71, 0x67, 0x32, 0x35, 0x35, 0x63, 0x77, 0x35, 0x6e, 0x76, 0x79, 0x36, 0x78, 0x39, 0x77, 0x72, 0x75, 0x66, 0x66, 0x6d, 0x70, 0x39, 0x75, 0x65, 0x7a, 0x72, 0x7a, 0x72, 0x37, 0x67, 0x63, 0x78, 0x35, 0x35, 0x39, 0x6b
                ],
                account: 8,
                diversifier_index: 0,
            },
            TestVector {
                p2pkh_bytes: None,
                p2sh_bytes: Some([
                    0x10, 0xac, 0xd2, 0x0b, 0x18, 0x3e, 0x31, 0xd4, 0x9f, 0x25, 0xc9, 0xa1, 0x38, 0xf4, 0x9b, 0x1a, 0x53, 0x7e, 0xdc, 0xf0
                ]),
                sapling_raw_addr: Some([
                    0x9b, 0x60, 0xae, 0x3d, 0x30, 0x22, 0x48, 0xb3, 0x49, 0xd6, 0x01, 0x56, 0x7e, 0x3d, 0x77, 0x95, 0xbf, 0xb3, 0x34, 0xea, 0x1f, 0xd1, 0xa7, 0xe7, 0x14, 0x02, 0x16, 0x9e, 0xbb, 0xe1, 0x4b, 0xd2, 0xce, 0xaa, 0x24, 0x4c, 0xcd, 0x6e, 0x5a, 0xa2, 0x24, 0x56, 0x13
                ]),
                orchard_raw_addr: Some([
                    0xe3, 0x40, 0x63, 0x65, 0x42, 0xec, 0xe1, 0xc8, 0x12, 0x85, 0xed, 0x4e, 0xab, 0x44, 0x8a, 0xdb, 0xb5, 0xa8, 0xc0, 0xf4, 0xd3, 0x86, 0xee, 0xff, 0x33, 0x7e, 0x88, 0xe6, 0x91, 0x5f, 0x6c, 0x3e, 0xc1, 0xb6, 0xea, 0x83, 0x5a, 0x88, 0xd5, 0x66, 0x12, 0xd2, 0xbd
                ]),
                unknown_typecode: 65531,
                unknown_bytes: None,
                unified_addr: vec![
                    0x75, 0x31, 0x7a, 0x65, 0x6b, 0x68, 0x68, 0x6d, 0x68, 0x6b, 0x35, 0x34, 0x78, 0x35, 0x63, 0x65, 0x35, 0x63, 0x33, 0x36, 0x72, 0x74, 0x37, 0x6e, 0x63, 0x32, 0x37, 0x35, 0x67, 0x65, 0x70, 0x37, 0x6e, 0x61, 0x76, 0x32, 0x6e, 0x73, 0x78, 0x34, 0x73, 0x68, 0x30, 0x61, 0x66, 0x6c, 0x6c, 0x75, 0x70, 0x39, 0x76, 0x72, 0x68, 0x35, 0x68, 0x73, 0x38, 0x36, 0x7a, 0x38, 0x73, 0x6b, 0x6a, 0x74, 0x64, 0x36, 0x64, 0x6e, 0x73, 0x6c, 0x76, 0x67, 0x73, 0x6d, 0x61, 0x74, 0x74, 0x30, 0x68, 0x38, 0x68, 0x32, 0x34, 0x37, 0x63, 0x67, 0x6e, 0x66, 0x6b, 0x73, 0x64, 0x6c, 0x77, 0x6c, 0x39, 0x78, 0x6d, 0x61, 0x72, 0x75, 0x79, 0x75, 0x70, 0x66, 0x6c, 0x74, 0x30, 0x64, 0x71, 0x66, 0x73, 0x63, 0x78, 0x30, 0x64, 0x79, 0x79, 0x65, 0x6d, 0x32, 0x66, 0x61, 0x61, 0x39, 0x77, 0x65, 0x71, 0x65, 0x33, 0x78, 0x61, 0x6b, 0x39, 0x77, 0x36, 0x65, 0x66, 0x72, 0x35, 0x34, 0x37, 0x63, 0x6a, 0x38, 0x32, 0x39, 0x72, 0x32, 0x74, 0x6e, 0x79, 0x74, 0x61, 0x30, 0x32, 0x68, 0x78, 0x66, 0x64, 0x78, 0x73, 0x64, 0x6a, 0x6d, 0x76, 0x39, 0x7a, 0x72, 0x35, 0x6b, 0x74, 0x6b, 0x70, 0x32, 0x30, 0x66, 0x70, 0x63, 0x78, 0x65, 0x61, 0x64, 0x68, 0x66, 0x72, 0x68, 0x30, 0x32, 0x61, 0x6b, 0x34, 0x61, 0x36, 0x68, 0x6e, 0x78, 0x76, 0x35, 0x73, 0x36, 0x37, 0x72, 0x67, 0x71, 0x72, 0x72, 0x76, 0x66, 0x70, 0x64, 0x6a, 0x74, 0x35
                ],
                account: 9,
                diversifier_index: 0,
            },
            TestVector {
                p2pkh_bytes: None,
                p2sh_bytes: Some([
                    0xaf, 0x9d, 0xb6, 0x99, 0x0e, 0xd8, 0x3d, 0xd6, 0x4a, 0xf3, 0x59, 0x7c, 0x04, 0x32, 0x3e, 0xa5, 0x1b, 0x00, 0x52, 0xad
                ]),
                sapling_raw_addr: None,
                orchard_raw_addr: Some([
                    0xcd, 0xf7, 0xfe, 0xd0, 0xd0, 0x82, 0x2f, 0xd8, 0x49, 0xcf, 0xfb, 0x20, 0xa4, 0xd5, 0xee, 0x70, 0x1a, 0xd8, 0x14, 0x1e, 0x66, 0xd8, 0x1d, 0xdf, 0xab, 0xf8, 0x78, 0x75, 0x11, 0x7c, 0x05, 0x09, 0x22, 0x40, 0x60, 0x3c, 0x54, 0x6b, 0x8d, 0xc1, 0x87, 0xcd, 0x8c
                ]),
                unknown_typecode: 65532,
                unknown_bytes: None,
                unified_addr: vec![
                    0x75, 0x31, 0x65, 0x35, 0x34, 0x71, 0x63, 0x6e, 0x30, 0x74, 0x65, 0x70, 0x79, 0x6c, 0x33, 0x30, 0x7a, 0x7a, 0x32, 0x66, 0x72, 0x67, 0x7a, 0x37, 0x71, 0x34, 0x61, 0x36, 0x6d, 0x73, 0x6e, 0x32, 0x65, 0x30, 0x32, 0x6e, 0x70, 0x76, 0x32, 0x6e, 0x66, 0x66, 0x73, 0x64, 0x33, 0x68, 0x35, 0x32, 0x33, 0x6d, 0x74, 0x78, 0x38, 0x64, 0x32, 0x32, 0x61, 0x6a, 0x76, 0x66, 0x76, 0x73, 0x71, 0x75, 0x72, 0x35, 0x73, 0x6a, 0x7a, 0x38, 0x76, 0x66, 0x6e, 0x6d, 0x77, 0x32, 0x79, 0x73, 0x36, 0x37, 0x30, 0x38, 0x71, 0x70, 0x38, 0x6b, 0x61, 0x39, 0x30, 0x6a, 0x35, 0x61, 0x34, 0x33, 0x30, 0x75, 0x79, 0x38, 0x76, 0x38, 0x33, 0x61, 0x6c, 0x6a, 0x63, 0x30, 0x63, 0x30, 0x35, 0x7a, 0x6a, 0x75, 0x35, 0x34, 0x78, 0x79, 0x35, 0x6e, 0x76, 0x77, 0x33, 0x6d, 0x66, 0x68, 0x6b, 0x37, 0x6e, 0x77, 0x37, 0x36, 0x6b, 0x6b, 0x79, 0x64, 0x79, 0x6c, 0x71, 0x34, 0x66, 0x65, 0x6c
                ],
                account: 10,
                diversifier_index: 0,
            },
            TestVector {
                p2pkh_bytes: None,
                p2sh_bytes: None,
                sapling_raw_addr: None,
                orchard_raw_addr: Some([
                    0x24, 0xfd, 0x59, 0xf3, 0x2b, 0x2d, 0x39, 0xdd, 0xe6, 0x6e, 0x46, 0xc3, 0x92, 0x06, 0xa3, 0x1b, 0xc0, 0x4f, 0xa5, 0xc6, 0x84, 0x79, 0x76, 0xea, 0x6b, 0xbd, 0x31, 0x63, 0xee, 0x14, 0xf5, 0x8f, 0x58, 0x4a, 0xcc, 0x13, 0x14, 0x79, 0xea, 0x55, 0x8d, 0x3f, 0x84
                ]),
                unknown_typecode: 65530,
                unknown_bytes: None,
                unified_addr: vec![
                    0x75, 0x31, 0x7a, 0x38, 0x77, 0x73, 0x72, 0x68, 0x6d, 0x66, 0x36, 0x6d, 0x39, 0x67, 0x76, 0x61, 0x36, 0x76, 0x6c, 0x33, 0x73, 0x7a, 0x63, 0x6b, 0x30, 0x36, 0x70, 0x39, 0x37, 0x30, 0x78, 0x35, 0x77, 0x68, 0x6d, 0x36, 0x33, 0x6a, 0x66, 0x6a, 0x32, 0x66, 0x72, 0x6d, 0x6d, 0x63, 0x39, 0x6e, 0x39, 0x75, 0x6d, 0x34, 0x79, 0x63, 0x73, 0x38, 0x79, 0x75, 0x74, 0x6a, 0x37, 0x67, 0x38, 0x33, 0x38, 0x76, 0x72, 0x67, 0x68, 0x32, 0x30, 0x6c, 0x66, 0x78, 0x79, 0x35, 0x32, 0x79, 0x30, 0x68, 0x32, 0x36, 0x74, 0x74, 0x38, 0x6e, 0x67, 0x76, 0x64, 0x32, 0x67, 0x79, 0x63, 0x70, 0x79, 0x71, 0x76, 0x39, 0x6b, 0x79, 0x30, 0x32, 0x71, 0x6b, 0x63, 0x73
                ],
                account: 11,
                diversifier_index: 0,
            },
            TestVector {
                p2pkh_bytes: None,
                p2sh_bytes: None,
                sapling_raw_addr: Some([
                    0x78, 0xd8, 0x5b, 0xd0, 0xdb, 0x63, 0x90, 0x43, 0x37, 0x79, 0x87, 0xcd, 0xd8, 0x14, 0xc6, 0x39, 0x00, 0x16, 0x96, 0x4b, 0x68, 0x40, 0x16, 0xfa, 0xf1, 0xad, 0x4f, 0x16, 0x6c, 0x5f, 0x72, 0x39, 0x9a, 0x5e, 0x8d, 0x46, 0x9e, 0xc6, 0xbe, 0xb8, 0x73, 0xd5, 0x5d
                ]),
                orchard_raw_addr: None,
                unknown_typecode: 65535,
                unknown_bytes: None,
                unified_addr: vec![
                    0x75, 0x31, 0x78, 0x61, 0x68, 0x6a, 0x33, 0x35, 0x70, 0x37, 0x6d, 0x76, 0x39, 0x75, 0x6c, 0x6b, 0x33, 0x37, 0x32, 0x73, 0x33, 0x76, 0x64, 0x65, 0x68, 0x71, 0x72, 0x66, 0x34, 0x38, 0x75, 0x30, 0x77, 0x64, 0x66, 0x33, 0x78, 0x6c, 0x37, 0x72, 0x78, 0x7a, 0x72, 0x70, 0x65, 0x34, 0x61, 0x30, 0x74, 0x68, 0x75, 0x38, 0x64, 0x30, 0x6d, 0x39, 0x6d, 0x79, 0x61, 0x61, 0x70, 0x78, 0x37, 0x6b, 0x35, 0x76, 0x78, 0x36, 0x74, 0x7a, 0x35, 0x70, 0x74, 0x63, 0x6a, 0x76, 0x63, 0x76, 0x75, 0x34, 0x64, 0x72, 0x66, 0x71, 0x37, 0x75, 0x37, 0x71, 0x77, 0x7a, 0x6d, 0x66, 0x75, 0x65, 0x33, 0x6b, 0x74, 0x38, 0x73, 0x76, 0x73, 0x63, 0x33, 0x73, 0x65, 0x35
                ],
                account: 12,
                diversifier_index: 0,
            },
            TestVector {
                p2pkh_bytes: Some([
                    0x35, 0x55, 0x02, 0x13, 0xf7, 0xcb, 0x1d, 0xb6, 0xf5, 0xc2, 0x98, 0xc1, 0x7a, 0x2b, 0x7e, 0xa3, 0x66, 0x7d, 0x75, 0x6b
                ]),
                p2sh_bytes: None,
                sapling_raw_addr: None,
                orchard_raw_addr: Some([
                    0x51, 0x78, 0x92, 0x4f, 0x70, 0x67, 0xea, 0xc2, 0x61, 0x04, 0x4c, 0xa2, 0x7b, 0xa3, 0xcf, 0x52, 0xf7, 0x98, 0x48, 0x69, 0x73, 0xaf, 0x07, 0x95, 0xe6, 0x15, 0x87, 0xaa, 0x1b, 0x1e, 0xca, 0xd3, 0x33, 0xdc, 0x52, 0x04, 0x97, 0xed, 0xc6, 0x1d, 0xf8, 0x89, 0x80
                ]),
                unknown_typecode: 65533,
                unknown_bytes: Some(vec![
                    0x91, 0xe0, 0x0c, 0x7a, 0x1d, 0x48, 0xaf, 0x04, 0x68, 0x27, 0x59, 0x1e, 0x97, 0x33, 0xa9, 0x7f, 0xa6, 0xb6, 0x79, 0xf3, 0xdc, 0x60, 0x1d, 0x00, 0x82, 0x85, 0xed, 0xcb, 0xda, 0xe6, 0x9c, 0xe8, 0xfc, 0x1b, 0xe4, 0xaa, 0xc0, 0x0f, 0xf2, 0x71, 0x1e, 0xbd, 0x93, 0x1d, 0xe5, 0x18, 0x85, 0x68, 0x78, 0xf7, 0x34, 0x76, 0xf2, 0x1a, 0x48, 0x2e, 0xc9, 0x37, 0x83, 0x65, 0xc8, 0xf7, 0x39, 0x3c, 0x94, 0xe2, 0x88, 0x53, 0x15, 0xeb, 0x46, 0x71, 0x09, 0x8b, 0x79, 0x53, 0x5e, 0x79, 0x0f, 0xe5, 0x3e, 0x29, 0xfe, 0xf2, 0xb3, 0x76, 0x66, 0x97, 0xac, 0x32, 0xb4, 0xf4, 0x73, 0xf4, 0x68, 0xa0, 0x08, 0xe7, 0x23, 0x89, 0xfc, 0x03, 0x88, 0x0d, 0x78, 0x0c, 0xb0, 0x7f, 0xcf, 0xaa, 0xbe, 0x3f, 0x1a, 0x84, 0xb2, 0x7d, 0xb5, 0x9a, 0x4a, 0x15, 0x3d, 0x88, 0x2d, 0x2b, 0x21, 0x03, 0x59, 0x65, 0x55, 0xed, 0x94, 0x94, 0xc6, 0xac, 0x89, 0x3c, 0x49, 0x72, 0x38, 0x33, 0xec, 0x89, 0x26, 0xc1
                ]),
                unified_addr: vec![
                    0x75, 0x31, 0x33, 0x36, 0x66, 0x37, 0x77, 0x37, 0x74, 0x73, 0x70, 0x61, 0x6a, 0x34, 0x76, 0x35, 0x65, 0x77, 0x79, 0x70, 0x74, 0x6c, 0x33, 0x61, 0x77, 0x34, 0x68, 0x71, 0x36, 0x36, 0x71, 0x6a, 0x34, 0x66, 0x34, 0x75, 0x71, 0x63, 0x68, 0x63, 0x7a, 0x34, 0x33, 0x6c, 0x6b, 0x68, 0x77, 0x61, 0x76, 0x6b, 0x7a, 0x79, 0x37, 0x35, 0x6b, 0x35, 0x33, 0x38, 0x6e, 0x36, 0x63, 0x68, 0x34, 0x6a, 0x66, 0x6e, 0x74, 0x6a, 0x6b, 0x66, 0x70, 0x35, 0x70, 0x6a, 0x72, 0x71, 0x64, 0x77, 0x6d, 0x75, 0x6e, 0x73, 0x38, 0x79, 0x6d, 0x32, 0x61, 0x33, 0x72, 0x75, 0x72, 0x68, 0x30, 0x6c, 0x67, 0x74, 0x76, 0x6e, 0x67, 0x39, 0x63, 0x35, 0x79, 0x67, 0x39, 0x77, 0x63, 0x71, 0x35, 0x36, 0x71, 0x68, 0x39, 0x33, 0x6b, 0x71, 0x75, 0x38, 0x34, 0x34, 0x6d, 0x36, 0x30, 0x72, 0x39, 0x33, 0x35, 0x67, 0x73, 0x6e, 0x72, 0x36, 0x74, 0x68, 0x78, 0x38, 0x33, 0x36, 0x7a, 0x6e, 0x36
                ],
                account: 13,
                diversifier_index: 0,
            },
            TestVector {
                p2pkh_bytes: Some([
                    0x0f, 0xdc, 0xf1, 0xad, 0x75, 0xa5, 0x98, 0xaa, 0x26, 0x44, 0x84, 0xd3, 0xe7, 0x86, 0x27, 0x90, 0x9c, 0x98, 0x5d, 0x56
                ]),
                p2sh_bytes: None,
                sapling_raw_addr: Some([
                    0xa7, 0x5a, 0x6d, 0xe4, 0x21, 0xd2, 0xad, 0x1e, 0xe8, 0xf4, 0xb2, 0x5e, 0x39, 0x8a, 0xdd, 0xa9, 0xc0, 0xaa, 0xa6, 0xab, 0x1f, 0x25, 0x18, 0x98, 0x1a, 0x9d, 0xdb, 0x1d, 0xe6, 0xa3, 0x95, 0x7d, 0x77, 0x84, 0x23, 0x32, 0xd6, 0x28, 0x9d, 0xbe, 0x94, 0xe8, 0x32
                ]),
                orchard_raw_addr: Some([
                    0xb2, 0x08, 0xc9, 0x23, 0x5c, 0x8d, 0x40, 0xe4, 0x9b, 0x76, 0x10, 0x0b, 0x2d, 0x01, 0x0f, 0x37, 0x83, 0xf1, 0x2c, 0x66, 0xe7, 0xd3, 0xbe, 0xb1, 0x17, 0xb2, 0xc9, 0x63, 0x21, 0xb7, 0xf6, 0x56, 0x2a, 0xdb, 0x4e, 0xfc, 0x14, 0x4e, 0x39, 0xd9, 0x09, 0xe7, 0x28
                ]),
                unknown_typecode: 65533,
                unknown_bytes: None,
                unified_addr: vec![
                    0x75, 0x31, 0x6d, 0x39, 0x36, 0x63, 0x36, 0x33, 0x6d, 0x32, 0x34, 0x39, 0x37, 0x71, 0x65, 0x30, 0x79, 0x74, 0x73, 0x61, 0x61, 0x65, 0x7a, 0x30, 0x36, 0x74, 0x74, 0x61, 0x78, 0x6d, 0x71, 0x74, 0x6c, 0x73, 0x38, 0x73, 0x30, 0x36, 0x75, 0x33, 0x79, 0x33, 0x30, 0x77, 0x32, 0x7a, 0x6c, 0x66, 0x78, 0x6d, 0x66, 0x77, 0x63, 0x33, 0x78, 0x74, 0x75, 0x71, 0x30, 0x73, 0x63, 0x67, 0x78, 0x75, 0x6a, 0x75, 0x63, 0x34, 0x37, 0x39, 0x35, 0x32, 0x77, 0x70, 0x63, 0x33, 0x74, 0x73, 0x74, 0x67, 0x6d, 0x71, 0x65, 0x38, 0x66, 0x77, 0x63, 0x6e, 0x61, 0x76, 0x79, 0x6c, 0x67, 0x65, 0x34, 0x7a, 0x7a, 0x32, 0x6a, 0x30, 0x63, 0x75, 0x70, 0x71, 0x72, 0x75, 0x32, 0x68, 0x6d, 0x72, 0x74, 0x38, 0x78, 0x6d, 0x6c, 0x76, 0x65, 0x67, 0x6a, 0x67, 0x72, 0x77, 0x30, 0x70, 0x74, 0x34, 0x72, 0x61, 0x63, 0x66, 0x35, 0x78, 0x6a, 0x78, 0x63, 0x6c, 0x35, 0x37, 0x64, 0x66, 0x77, 0x36, 0x6a, 0x68, 0x73, 0x70, 0x32, 0x64, 0x65, 0x6a, 0x39, 0x73, 0x7a, 0x34, 0x6b, 0x73, 0x79, 0x63, 0x6e, 0x73, 0x75, 0x68, 0x73, 0x76, 0x6a, 0x6d, 0x66, 0x37, 0x63, 0x72, 0x6c, 0x63, 0x35, 0x63, 0x6b, 0x75, 0x35, 0x38, 0x30, 0x32, 0x32, 0x79, 0x36, 0x71, 0x35, 0x68, 0x70, 0x70, 0x65, 0x70, 0x36, 0x71, 0x6e, 0x70, 0x39, 0x65, 0x63, 0x39, 0x78, 0x61, 0x33, 0x79, 0x68, 0x36, 0x71, 0x74, 0x37, 0x6a, 0x36, 0x67, 0x7a, 0x65, 0x77
                ],
                account: 14,
                diversifier_index: 0,
            },
            TestVector {
                p2pkh_bytes: None,
                p2sh_bytes: None,
                sapling_raw_addr: None,
                orchard_raw_addr: Some([
                    0x9e, 0x54, 0x45, 0xd6, 0xcd, 0x3c, 0xb9, 0xf9, 0x8b, 0x0d, 0xf1, 0x06, 0x2b, 0xda, 0x47, 0xad, 0xff, 0xd5, 0xa6, 0x6c, 0x0c, 0x2c, 0x48, 0x3c, 0x8b, 0xf1, 0x5c, 0x31, 0x76, 0xd7, 0x55, 0x91, 0x4a, 0x35, 0x76, 0x49, 0x6b, 0x5c, 0x35, 0xfe, 0xe2, 0x8a, 0x88
                ]),
                unknown_typecode: 65531,
                unknown_bytes: None,
                unified_addr: vec![
                    0x75, 0x31, 0x6a, 0x67, 0x6c, 0x68, 0x6a, 0x32, 0x6d, 0x61, 0x79, 0x36, 0x64, 0x66, 0x74, 0x77, 0x7a, 0x39, 0x75, 0x32, 0x71, 0x79, 0x6e, 0x78, 0x6a, 0x71, 0x7a, 0x6e, 0x75, 0x74, 0x36, 0x37, 0x34, 0x37, 0x68, 0x61, 0x73, 0x75, 0x30, 0x6d, 0x64, 0x6d, 0x6c, 0x63, 0x30, 0x32, 0x66, 0x63, 0x61, 0x73, 0x75, 0x61, 0x78, 0x75, 0x67, 0x64, 0x79, 0x7a, 0x77, 0x6a, 0x32, 0x6c, 0x38, 0x34, 0x6d, 0x6a, 0x39, 0x66, 0x67, 0x7a, 0x6a, 0x37, 0x79, 0x30, 0x6b, 0x39, 0x66, 0x63, 0x70, 0x6a, 0x37, 0x33, 0x36, 0x73, 0x6c, 0x6d, 0x6a, 0x38, 0x67, 0x6b, 0x37, 0x37, 0x75, 0x67, 0x38, 0x6c, 0x6c, 0x61, 0x76, 0x63, 0x67, 0x32, 0x6c, 0x66, 0x6d, 0x6d
                ],
                account: 15,
                diversifier_index: 0,
            },
            TestVector {
                p2pkh_bytes: Some([
                    0xee, 0x2a, 0x6a, 0x1c, 0xbc, 0x5a, 0x84, 0xe3, 0x44, 0xd2, 0x82, 0x30, 0xcb, 0xea, 0x9a, 0x65, 0x47, 0x5a, 0xca, 0x79
                ]),
                p2sh_bytes: None,
                sapling_raw_addr: None,
                orchard_raw_addr: Some([
                    0x25, 0x98, 0xd8, 0x4d, 0xff, 0xb3, 0x4f, 0x59, 0x08, 0xb9, 0x07, 0x32, 0x49, 0x0f, 0x38, 0x81, 0x39, 0x91, 0x50, 0xd4, 0xc6, 0x94, 0xfc, 0xe9, 0xbf, 0x30, 0xd1, 0x56, 0x0b, 0x2c, 0x56, 0xf0, 0x98, 0x29, 0xfe, 0x12, 0x3b, 0x9a, 0xdd, 0x20, 0xe5, 0xd7, 0x1c
                ]),
                unknown_typecode: 65534,
                unknown_bytes: None,
                unified_addr: vec![
                    0x75, 0x31, 0x37, 0x36, 0x79, 0x39, 0x66, 0x35, 0x74, 0x64, 0x34, 0x33, 0x61, 0x74, 0x68, 0x70, 0x66, 0x71, 0x65, 0x38, 0x33, 0x6a, 0x66, 0x35, 0x71, 0x64, 0x71, 0x65, 0x64, 0x68, 0x6d, 0x30, 0x77, 0x7a, 0x68, 0x6e, 0x6a, 0x67, 0x39, 0x66, 0x6c, 0x7a, 0x63, 0x74, 0x65, 0x66, 0x39, 0x72, 0x6d, 0x30, 0x7a, 0x73, 0x74, 0x66, 0x68, 0x72, 0x67, 0x7a, 0x39, 0x34, 0x64, 0x68, 0x68, 0x67, 0x32, 0x72, 0x64, 0x79, 0x71, 0x34, 0x34, 0x39, 0x79, 0x33, 0x61, 0x79, 0x75, 0x32, 0x36, 0x61, 0x6e, 0x6d, 0x66, 0x74, 0x37, 0x78, 0x6d, 0x6a, 0x39, 0x36, 0x67, 0x6a, 0x33, 0x36, 0x30, 0x64, 0x37, 0x33, 0x74, 0x37, 0x30, 0x30, 0x75, 0x6c, 0x73, 0x7a, 0x71, 0x38, 0x71, 0x6b, 0x38, 0x32, 0x36, 0x6b, 0x67, 0x64, 0x72, 0x6a, 0x64, 0x6c, 0x71, 0x38, 0x71, 0x76, 0x66, 0x32, 0x6b, 0x63, 0x32, 0x68, 0x38, 0x64, 0x67, 0x73, 0x71, 0x78, 0x37, 0x38, 0x79, 0x30, 0x75
                ],
                account: 16,
                diversifier_index: 0,
            },
            TestVector {
                p2pkh_bytes: None,
                p2sh_bytes: None,
                sapling_raw_addr: Some([
                    0xd3, 0xa8, 0x03, 0x80, 0x3f, 0xee, 0xe7, 0xa0, 0x32, 0xa2, 0x4a, 0xdf, 0xaa, 0x8f, 0x6a, 0x94, 0xce, 0xcb, 0x96, 0x71, 0xc1, 0x33, 0x3d, 0x0d, 0x5d, 0x1a, 0x3d, 0x79, 0xd8, 0x2b, 0xc3, 0x10, 0x72, 0x7c, 0x66, 0x53, 0x64, 0xd7, 0x10, 0x22, 0x55, 0x9c, 0x50
                ]),
                orchard_raw_addr: Some([
                    0x7c, 0x98, 0xb8, 0xf6, 0x13, 0xf9, 0xff, 0x02, 0x74, 0x6b, 0xea, 0x2a, 0x16, 0x7c, 0xfd, 0x1b, 0xd3, 0xa1, 0x86, 0x2a, 0xf9, 0x63, 0x1b, 0xf6, 0x1d, 0x9d, 0x60, 0x4e, 0x08, 0x24, 0xe2, 0xcb, 0x84, 0x67, 0xa1, 0xe5, 0x49, 0xdb, 0x87, 0xa7, 0x6e, 0x7a, 0x8a
                ]),
                unknown_typecode: 65535,
                unknown_bytes: None,
                unified_addr: vec![
                    0x75, 0x31, 0x61, 0x36, 0x34, 0x6c, 0x30, 0x39, 0x71, 0x72, 0x73, 0x78, 0x75, 0x6c, 0x66, 0x6a, 0x7a, 0x6e, 0x6d, 0x36, 0x6b, 0x32, 0x67, 0x35, 0x33, 0x35, 0x75, 0x73, 0x79, 0x68, 0x74, 0x61, 0x66, 0x38, 0x65, 0x64, 0x36, 0x30, 0x76, 0x34, 0x6a, 0x72, 0x6a, 0x6d, 0x6b, 0x77, 0x76, 0x6b, 0x75, 0x78, 0x34, 0x74, 0x37, 0x70, 0x64, 0x79, 0x63, 0x33, 0x6e, 0x6b, 0x7a, 0x72, 0x65, 0x66, 0x64, 0x67, 0x74, 0x6e, 0x77, 0x38, 0x34, 0x32, 0x30, 0x6c, 0x6a, 0x38, 0x73, 0x68, 0x6d, 0x30, 0x35, 0x6a, 0x61, 0x39, 0x66, 0x78, 0x78, 0x67, 0x6e, 0x68, 0x72, 0x61, 0x39, 0x32, 0x6e, 0x68, 0x73, 0x71, 0x35, 0x36, 0x67, 0x78, 0x38, 0x63, 0x32, 0x70, 0x75, 0x7a, 0x33, 0x66, 0x6b, 0x6b, 0x67, 0x6e, 0x72, 0x6b, 0x71, 0x66, 0x35, 0x79, 0x75, 0x71, 0x66, 0x64, 0x74, 0x66, 0x37, 0x74, 0x36, 0x72, 0x61, 0x6e, 0x34, 0x37, 0x67, 0x64, 0x63, 0x66, 0x35, 0x76, 0x76, 0x64, 0x66, 0x61, 0x63, 0x7a, 0x77, 0x66, 0x33, 0x75, 0x75, 0x79, 0x34, 0x66, 0x79, 0x73, 0x68, 0x33, 0x6d, 0x7a, 0x75, 0x38, 0x68, 0x64, 0x35, 0x74, 0x6b, 0x6c, 0x30, 0x35, 0x6d, 0x76, 0x72, 0x67, 0x65, 0x39, 0x6e, 0x38
                ],
                account: 17,
                diversifier_index: 0,
            },
            TestVector {
                p2pkh_bytes: Some([
                    0x42, 0x99, 0x40, 0xf2, 0x66, 0xcc, 0x16, 0x5b, 0xed, 0x0c, 0xb1, 0xb8, 0xd4, 0xf8, 0xf6, 0x4f, 0x3f, 0x1e, 0x82, 0xf4
                ]),
                p2sh_bytes: None,
                sapling_raw_addr: None,
                orchard_raw_addr: Some([
                    0xa8, 0x04, 0x05, 0xd5, 0x56, 0x8a, 0xb8, 0xab, 0x8f, 0x85, 0x46, 0x16, 0x3d, 0x95, 0x1a, 0xb2, 0x97, 0xfd, 0x5e, 0x6f, 0x43, 0xe7, 0xfc, 0xeb, 0xcb, 0x66, 0x4f, 0xea, 0xcf, 0xab, 0x5a, 0xfd, 0x80, 0xaa, 0xf7, 0xf3, 0x54, 0xc0, 0x7a, 0x99, 0x01, 0x78, 0x8c
                ]),
                unknown_typecode: 65535,
                unknown_bytes: None,
                unified_addr: vec![
                    0x75, 0x31, 0x73, 0x6b, 0x77, 0x35, 0x71, 0x6b, 0x75, 0x35, 0x38, 0x61, 0x33, 0x72, 0x77, 0x7a, 0x6a, 0x39, 0x7a, 0x61, 0x79, 0x6c, 0x7a, 0x79, 0x6a, 0x7a, 0x75, 0x6d, 0x6e, 0x6a, 0x78, 0x32, 0x35, 0x76, 0x77, 0x63, 0x6a, 0x6e, 0x39, 0x78, 0x71, 0x63, 0x76, 0x61, 0x37, 0x63, 0x6c, 0x68, 0x6a, 0x67, 0x72, 0x6e, 0x32, 0x6b, 0x6b, 0x72, 0x6c, 0x6c, 0x39, 0x77, 0x32, 0x35, 0x63, 0x6e, 0x78, 0x76, 0x65, 0x63, 0x65, 0x70, 0x38, 0x6d, 0x32, 0x61, 0x76, 0x35, 0x75, 0x65, 0x64, 0x65, 0x39, 0x6c, 0x72, 0x33, 0x64, 0x70, 0x64, 0x66, 0x63, 0x61, 0x65, 0x37, 0x66, 0x75, 0x33, 0x75, 0x35, 0x71, 0x78, 0x30, 0x63, 0x74, 0x79, 0x38, 0x38, 0x6d, 0x73, 0x77, 0x6c, 0x36, 0x74, 0x32, 0x66, 0x6b, 0x64, 0x6d, 0x37, 0x67, 0x64, 0x73, 0x6e, 0x76, 0x64, 0x75, 0x30, 0x75, 0x37, 0x71, 0x30, 0x39, 0x70, 0x6d, 0x30, 0x39, 0x67, 0x77, 0x7a, 0x6b, 0x67, 0x35, 0x72
                ],
                account: 18,
                diversifier_index: 0,
            },
            TestVector {
                p2pkh_bytes: None,
                p2sh_bytes: None,
                sapling_raw_addr: Some([
                    0x86, 0x60, 0x07, 0x0e, 0x37, 0x57, 0xff, 0x65, 0x07, 0x06, 0x07, 0x91, 0xfd, 0x69, 0x4f, 0x6a, 0x63, 0x1b, 0x84, 0x95, 0xa2, 0xb7, 0x4f, 0xfa, 0x39, 0x23, 0x6c, 0xf6, 0x53, 0xca, 0xea, 0x55, 0x75, 0xb8, 0x6a, 0xf3, 0x20, 0x0b, 0x01, 0x0e, 0x51, 0x3b, 0xab
                ]),
                orchard_raw_addr: Some([
                    0x63, 0xb7, 0xb7, 0x06, 0xd9, 0x91, 0x16, 0x99, 0x86, 0xae, 0xe5, 0x61, 0x33, 0xf0, 0xa5, 0x0b, 0x2a, 0x0c, 0x82, 0x25, 0xfb, 0xa6, 0xda, 0xe9, 0x51, 0x76, 0x00, 0x7b, 0x1f, 0x02, 0x3a, 0x1e, 0x97, 0xc1, 0xaa, 0x36, 0x6e, 0x99, 0xbf, 0x97, 0x0f, 0xda, 0x82
                ]),
                unknown_typecode: 65534,
                unknown_bytes: None,
                unified_addr: vec![
                    0x75, 0x31, 0x76, 0x67, 0x36, 0x32, 0x6d, 0x67, 0x6a, 0x64, 0x64, 0x6e, 0x6c, 0x76, 0x35, 0x77, 0x36, 0x6c, 0x64, 0x6b, 0x79, 0x32, 0x78, 0x65, 0x30, 0x63, 0x38, 0x74, 0x65, 0x74, 0x6d, 0x63, 0x38, 0x32, 0x74, 0x75, 0x39, 0x76, 0x6c, 0x7a, 0x7a, 0x6b, 0x75, 0x79, 0x6e, 0x78, 0x34, 0x39, 0x66, 0x6e, 0x75, 0x71, 0x6a, 0x76, 0x78, 0x6a, 0x74, 0x35, 0x64, 0x67, 0x6e, 0x33, 0x63, 0x6d, 0x38, 0x74, 0x35, 0x6e, 0x38, 0x35, 0x7a, 0x63, 0x71, 0x35, 0x6c, 0x6a, 0x72, 0x74, 0x67, 0x37, 0x7a, 0x6d, 0x77, 0x68, 0x6b, 0x37, 0x30, 0x68, 0x36, 0x72, 0x64, 0x6d, 0x63, 0x6c, 0x66, 0x37, 0x73, 0x63, 0x78, 0x78, 0x6e, 0x67, 0x75, 0x6b, 0x35, 0x66, 0x6c, 0x76, 0x66, 0x32, 0x61, 0x70, 0x70, 0x37, 0x36, 0x78, 0x75, 0x39, 0x30, 0x37, 0x63, 0x6d, 0x6a, 0x79, 0x6c, 0x78, 0x76, 0x73, 0x65, 0x6e, 0x32, 0x35, 0x78, 0x65, 0x39, 0x76, 0x37, 0x76, 0x33, 0x6b, 0x72, 0x73, 0x78, 0x61, 0x39, 0x75, 0x79, 0x30, 0x76, 0x32, 0x6a, 0x6a, 0x71, 0x33, 0x37, 0x6b, 0x68, 0x34, 0x79, 0x6d, 0x6c, 0x61, 0x66, 0x6e, 0x38, 0x70, 0x65, 0x76, 0x71, 0x61, 0x6c, 0x71, 0x61, 0x34, 0x64, 0x6d, 0x36, 0x37
                ],
                account: 19,
                diversifier_index: 5,
            },
        ];
