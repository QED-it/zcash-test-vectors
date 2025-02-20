        struct TestVector {
            input: [[u8; 32]; 2],
            output: [u8; 32],
        }

        // From https://github.com/zcash-hackworks/zcash-test-vectors/blob/master/orchard_poseidon_hash.py
        const TEST_VECTORS: &[TestVector] = &[
            TestVector {
                input: [
                    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                    [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                ],
                output: [
                    0x83, 0x58, 0xd7, 0x11, 0xa0, 0x32, 0x9d, 0x38, 0xbe, 0xcd, 0x54, 0xfb, 0xa7, 0xc2, 0x83, 0xed, 0x3e, 0x08, 0x9a, 0x39, 0xc9, 0x1b, 0x6a, 0x9d, 0x10, 0xef, 0xb0, 0x2b, 0xc3, 0xf1, 0x2f, 0x06
                ],
            },
            TestVector {
                input: [
                    [0x5c, 0x7a, 0x8f, 0x73, 0xad, 0xfc, 0x70, 0xfb, 0x3f, 0x13, 0x94, 0x49, 0xac, 0x6b, 0x57, 0x07, 0x4c, 0x4d, 0x6e, 0x66, 0xb1, 0x64, 0x93, 0x9d, 0xaf, 0xfa, 0x2e, 0xf6, 0xee, 0x69, 0x21, 0x08],
                    [0x1a, 0xdd, 0x86, 0xb3, 0xf2, 0xe1, 0xbd, 0xa6, 0x2a, 0x5d, 0x2e, 0x0e, 0x98, 0x2b, 0x77, 0xe6, 0xb0, 0xef, 0x9c, 0xa3, 0xf2, 0x49, 0x88, 0xc7, 0xb3, 0x53, 0x42, 0x01, 0xcf, 0xb1, 0xcd, 0x0d],
                ],
                output: [
                    0xdb, 0x26, 0x75, 0xff, 0x3e, 0xf8, 0xfe, 0x30, 0xc4, 0xd5, 0xde, 0x61, 0xca, 0xc0, 0x2a, 0x8e, 0xf1, 0xa0, 0x85, 0x23, 0xbe, 0x92, 0x39, 0x4b, 0x79, 0xd2, 0x67, 0x26, 0x30, 0x3b, 0xe6, 0x03
                ],
            },
            TestVector {
                input: [
                    [0xbd, 0x69, 0xb8, 0x25, 0x32, 0xb6, 0x94, 0x0f, 0xf2, 0x59, 0x0f, 0x67, 0x9b, 0xa9, 0xc7, 0x27, 0x1f, 0xe0, 0x1f, 0x7e, 0x9c, 0x8e, 0x36, 0xd6, 0xa5, 0xe2, 0x9d, 0x4e, 0x30, 0xa7, 0x35, 0x14],
                    [0xbc, 0x50, 0x98, 0x42, 0x55, 0xd6, 0xaf, 0xbe, 0x9e, 0xf9, 0x28, 0x48, 0xed, 0x5a, 0xc0, 0x08, 0x62, 0xc2, 0xfa, 0x7b, 0x2f, 0xec, 0xbc, 0xb6, 0x4b, 0x69, 0x68, 0x91, 0x2a, 0x63, 0x81, 0x0e],
                ],
                output: [
                    0xf5, 0x12, 0x1d, 0x1e, 0x1d, 0x5c, 0xfe, 0x8d, 0xa8, 0x96, 0xac, 0x0f, 0x9c, 0x18, 0x3d, 0x76, 0x00, 0x31, 0xf6, 0xef, 0x8c, 0x7a, 0x41, 0xe6, 0x5e, 0xb0, 0x07, 0xcd, 0xdc, 0x1d, 0x14, 0x3d
                ],
            },
            TestVector {
                input: [
                    [0x3d, 0xc1, 0x66, 0xd5, 0x6a, 0x1d, 0x62, 0xf5, 0xa8, 0xd7, 0x55, 0x1d, 0xb5, 0xfd, 0x93, 0x13, 0xe8, 0xc7, 0x20, 0x3d, 0x99, 0x6a, 0xf7, 0xd4, 0x77, 0x08, 0x37, 0x56, 0xd5, 0x9a, 0xf8, 0x0d],
                    [0x05, 0xa7, 0x45, 0xf4, 0x5d, 0x7f, 0xf6, 0xdb, 0x10, 0xbc, 0x67, 0xfd, 0xf0, 0xf0, 0x3e, 0xbf, 0x81, 0x30, 0xab, 0x33, 0x36, 0x26, 0x97, 0xb0, 0xe4, 0xe4, 0xc7, 0x63, 0xcc, 0xb8, 0xf6, 0x36],
                ],
                output: [
                    0xa4, 0x16, 0xa5, 0xe7, 0x13, 0x51, 0x36, 0xa0, 0x50, 0x56, 0x90, 0x00, 0x58, 0xfa, 0x50, 0xbf, 0x18, 0x6a, 0xd7, 0x33, 0x90, 0xac, 0xe6, 0x32, 0x3d, 0x8d, 0x81, 0xaa, 0x8a, 0xdb, 0xd4, 0x11
                ],
            },
            TestVector {
                input: [
                    [0x49, 0x5c, 0x22, 0x2f, 0x7f, 0xba, 0x1e, 0x31, 0xde, 0xfa, 0x3d, 0x5a, 0x57, 0xef, 0xc2, 0xe1, 0xe9, 0xb0, 0x1a, 0x03, 0x55, 0x87, 0xd5, 0xfb, 0x1a, 0x38, 0xe0, 0x1d, 0x94, 0x90, 0x3d, 0x3c],
                    [0x3d, 0x0a, 0xd3, 0x36, 0x1f, 0xec, 0x09, 0x77, 0x90, 0xd9, 0xbe, 0x0e, 0x42, 0x98, 0x8d, 0x7d, 0x25, 0xc9, 0xa1, 0x38, 0xf4, 0x9b, 0x1a, 0x53, 0x7e, 0xdc, 0xf0, 0x4b, 0xe3, 0x4a, 0x98, 0x11],
                ],
                output: [
                    0x1a, 0xba, 0xf3, 0x06, 0xfe, 0xd0, 0x5f, 0xa8, 0x92, 0x84, 0x8c, 0x49, 0xf6, 0xba, 0x10, 0x41, 0x63, 0x43, 0x3f, 0x3f, 0x63, 0x31, 0x08, 0xa1, 0x3b, 0xc1, 0x5b, 0x2a, 0x1d, 0x55, 0xd4, 0x0c
                ],
            },
            TestVector {
                input: [
                    [0xa4, 0xaf, 0x9d, 0xb6, 0xd2, 0x7b, 0x50, 0x72, 0x83, 0x5f, 0x0c, 0x3e, 0x88, 0x39, 0x5e, 0xd7, 0xa4, 0x1b, 0x00, 0x52, 0xad, 0x80, 0x84, 0xa8, 0xb9, 0xda, 0x94, 0x8d, 0x32, 0x0d, 0xad, 0x16],
                    [0x4d, 0x54, 0x31, 0xe6, 0x43, 0x7d, 0x0b, 0x5b, 0xed, 0xbb, 0xcd, 0xaf, 0x34, 0x5b, 0x86, 0xc4, 0x12, 0x1f, 0xc0, 0x0f, 0xe7, 0xf2, 0x35, 0x73, 0x42, 0x76, 0xd3, 0x8d, 0x47, 0xf1, 0xe1, 0x11],
                ],
                output: [
                    0x04, 0xa1, 0x8a, 0xeb, 0x59, 0x3f, 0x79, 0x0b, 0x76, 0xa3, 0x99, 0xb7, 0xc1, 0x52, 0x8a, 0xcd, 0xed, 0xe9, 0x3b, 0x3b, 0x2c, 0x49, 0x6b, 0xd7, 0x1b, 0xd5, 0x87, 0xcb, 0xd7, 0xcf, 0xdf, 0x35
                ],
            },
            TestVector {
                input: [
                    [0xdd, 0x0c, 0x7a, 0x1d, 0x81, 0x1c, 0x7d, 0x9c, 0xd4, 0x6d, 0x37, 0x7b, 0x3f, 0xde, 0xab, 0x3f, 0xb6, 0x79, 0xf3, 0xdc, 0x60, 0x1d, 0x00, 0x82, 0x85, 0xed, 0xcb, 0xda, 0xe6, 0x9c, 0xe8, 0x3c],
                    [0x19, 0xe4, 0xaa, 0xc0, 0x35, 0x90, 0x17, 0xec, 0x85, 0xa1, 0x83, 0xd2, 0x20, 0x53, 0xdb, 0x33, 0xf7, 0x34, 0x76, 0xf2, 0x1a, 0x48, 0x2e, 0xc9, 0x37, 0x83, 0x65, 0xc8, 0xf7, 0x39, 0x3c, 0x14],
                ],
                output: [
                    0x11, 0x03, 0xcc, 0xdc, 0x00, 0xd0, 0xf3, 0x5f, 0x65, 0x83, 0x14, 0x11, 0x6b, 0xc2, 0xbc, 0xd9, 0x43, 0x74, 0xa9, 0x1f, 0xf9, 0x87, 0x7e, 0x70, 0x66, 0x33, 0x29, 0x04, 0x2b, 0xd2, 0xf6, 0x1f
                ],
            },
            TestVector {
                input: [
                    [0xe2, 0x88, 0x53, 0x15, 0xeb, 0x46, 0x71, 0x09, 0x8b, 0x79, 0x53, 0x5e, 0x79, 0x0f, 0xe5, 0x3e, 0x29, 0xfe, 0xf2, 0xb3, 0x76, 0x66, 0x97, 0xac, 0x32, 0xb4, 0xf4, 0x73, 0xf4, 0x68, 0xa0, 0x08],
                    [0xe6, 0x23, 0x89, 0xfc, 0x16, 0x57, 0xe0, 0xde, 0xf0, 0xb6, 0x32, 0xc6, 0xae, 0x25, 0xf9, 0xf7, 0x83, 0xb2, 0x7d, 0xb5, 0x9a, 0x4a, 0x15, 0x3d, 0x88, 0x2d, 0x2b, 0x21, 0x03, 0x59, 0x65, 0x15],
                ],
                output: [
                    0xf8, 0xf8, 0xc6, 0x5f, 0x43, 0x7c, 0x45, 0xbe, 0xac, 0x11, 0xeb, 0x7d, 0x9e, 0x47, 0x58, 0x6d, 0x87, 0x9a, 0xfd, 0x6f, 0x93, 0x04, 0x35, 0xbe, 0x0c, 0x01, 0xd1, 0x9c, 0x89, 0x5b, 0x8d, 0x10
                ],
            },
            TestVector {
                input: [
                    [0xeb, 0x94, 0x94, 0xc6, 0xd2, 0x27, 0xe2, 0x16, 0x3b, 0x46, 0x99, 0xd9, 0x91, 0xf4, 0x33, 0xbf, 0x94, 0x86, 0xa7, 0xaf, 0xcf, 0x4a, 0x0d, 0x9c, 0x73, 0x1e, 0x98, 0x5d, 0x99, 0x58, 0x9c, 0x0b],
                    [0xb7, 0x38, 0xe8, 0xaa, 0x0a, 0x15, 0x26, 0xa5, 0xbd, 0xef, 0x61, 0x31, 0x20, 0x37, 0x2e, 0x83, 0x1a, 0x20, 0xda, 0x8a, 0xba, 0x18, 0xd1, 0xdb, 0xeb, 0xbc, 0x86, 0x2d, 0xed, 0x42, 0x43, 0x1e],
                ],
                output: [
                    0x5a, 0xeb, 0x48, 0x96, 0x21, 0xb0, 0x2e, 0x8e, 0x69, 0x27, 0xb9, 0x4f, 0xd2, 0x9a, 0x61, 0x01, 0x83, 0xdf, 0x7f, 0x42, 0x87, 0xe9, 0xcb, 0xf1, 0xcc, 0xc8, 0x81, 0xd7, 0xd0, 0xb7, 0x38, 0x27
                ],
            },
            TestVector {
                input: [
                    [0x91, 0x47, 0x69, 0x30, 0xe3, 0x38, 0x5c, 0xd3, 0xe3, 0x37, 0x9e, 0x38, 0x53, 0xd9, 0x34, 0x67, 0xe0, 0x01, 0xaf, 0xa2, 0xfb, 0x8d, 0xc3, 0x43, 0x6d, 0x75, 0xa4, 0xa6, 0xf2, 0x65, 0x72, 0x10],
                    [0x4b, 0x19, 0x22, 0x32, 0xec, 0xb9, 0xf0, 0xc0, 0x24, 0x11, 0xe5, 0x25, 0x96, 0xbc, 0x5e, 0x90, 0x45, 0x7e, 0x74, 0x59, 0x39, 0xff, 0xed, 0xbd, 0x12, 0x86, 0x3c, 0xe7, 0x1a, 0x02, 0xaf, 0x11],
                ],
                output: [
                    0xb0, 0x14, 0x47, 0x20, 0xf5, 0xf2, 0xa2, 0x5d, 0x49, 0x2a, 0x50, 0x4e, 0xc0, 0x73, 0x7f, 0x09, 0x7e, 0xd8, 0x52, 0x17, 0x4f, 0x55, 0xf5, 0x86, 0x30, 0x91, 0x30, 0x6c, 0x1a, 0xf2, 0x00, 0x35
                ],
            },
            TestVector {
                input: [
                    [0x7b, 0x41, 0x7a, 0xdb, 0x63, 0xb3, 0x71, 0x22, 0xa5, 0xbf, 0x62, 0xd2, 0x6f, 0x1e, 0x7f, 0x26, 0x8f, 0xb8, 0x6b, 0x12, 0xb5, 0x6d, 0xa9, 0xc3, 0x82, 0x85, 0x7d, 0xee, 0xcc, 0x40, 0xa9, 0x0d],
                    [0x5e, 0x29, 0x35, 0x39, 0x71, 0xb3, 0x49, 0x94, 0xb6, 0x21, 0xb0, 0xb2, 0x61, 0xae, 0xb3, 0x78, 0x6d, 0xd9, 0x84, 0xd5, 0x67, 0xdb, 0x28, 0x57, 0xb9, 0x27, 0xb7, 0xfa, 0xe2, 0xdb, 0x58, 0x31],
                ],
                output: [
                    0xbb, 0xbe, 0xb7, 0x42, 0xd6, 0xe7, 0xc0, 0x1a, 0xdb, 0xf4, 0xd3, 0x85, 0x5e, 0x35, 0xfe, 0xc4, 0x62, 0x04, 0x30, 0x89, 0xc1, 0x8b, 0xa8, 0x02, 0x90, 0x64, 0x7b, 0xb0, 0xe5, 0x81, 0xad, 0x11
                ],
            },
        ];
