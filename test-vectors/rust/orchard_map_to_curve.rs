pub(crate) struct TestVector {
    pub(crate) u: [u8; 32],
    pub(crate) point: [u8; 32],
}

// From https://github.com/zcash-hackworks/zcash-test-vectors/blob/master/orchard_map_to_curve.py
pub(crate) fn test_vectors() -> Vec<TestVector> {
    vec![
            TestVector {
                u: [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                ],
                point: [
                    0x00, 0x38, 0xa6, 0xbc, 0x53, 0x32, 0x33, 0xaf, 0x74, 0xb6, 0xe2, 0xe0, 0x5c, 0x6e, 0xca, 0xf6, 0x60, 0x71, 0xc6, 0xa0, 0xf1, 0x5b, 0x58, 0xe9, 0x3d, 0xf0, 0x6b, 0xd2, 0x31, 0x07, 0x15, 0x2c
                ],
            },
            TestVector {
                u: [
                    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                ],
                point: [
                    0x20, 0xa1, 0x3b, 0xbf, 0x7d, 0x67, 0x1d, 0xce, 0x4a, 0xc9, 0xfc, 0xd9, 0xf9, 0xf5, 0x07, 0x14, 0x39, 0x2c, 0x28, 0xc4, 0xe1, 0xe9, 0xe0, 0x37, 0x33, 0x78, 0xc9, 0x72, 0xfb, 0x22, 0xb2, 0x8b
                ],
            },
            TestVector {
                u: [
                    0x23, 0x01, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0xf1, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0xf1, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12
                ],
                point: [
                    0x23, 0x57, 0xb2, 0x97, 0xef, 0x83, 0x0b, 0x04, 0x6c, 0xd7, 0x8e, 0x81, 0x18, 0x74, 0x2b, 0xa1, 0xa9, 0x65, 0x8e, 0xda, 0x8f, 0xc1, 0x03, 0x9c, 0xc3, 0xdb, 0x36, 0xd5, 0x64, 0x7f, 0xf2, 0xa4
                ],
            },
            TestVector {
                u: [
                    0x5c, 0x7a, 0x8f, 0x73, 0xad, 0xfc, 0x70, 0xfb, 0x3f, 0x13, 0x94, 0x49, 0xac, 0x6b, 0x57, 0x07, 0x4c, 0x4d, 0x6e, 0x66, 0xb1, 0x64, 0x93, 0x9d, 0xaf, 0xfa, 0x2e, 0xf6, 0xee, 0x69, 0x21, 0x08
                ],
                point: [
                    0x14, 0x26, 0x6f, 0xf4, 0x55, 0x3e, 0x4a, 0x13, 0x35, 0x70, 0xa0, 0xa4, 0x4b, 0x6e, 0x9b, 0x47, 0x33, 0x2e, 0xab, 0x00, 0x77, 0xbb, 0x13, 0x2b, 0xbc, 0x06, 0x0a, 0xcc, 0x4b, 0xfe, 0x60, 0x37
                ],
            },
            TestVector {
                u: [
                    0x1a, 0xdd, 0x86, 0xb3, 0xf2, 0xe1, 0xbd, 0xa6, 0x2a, 0x5d, 0x2e, 0x0e, 0x98, 0x2b, 0x77, 0xe6, 0xb0, 0xef, 0x9c, 0xa3, 0xf2, 0x49, 0x88, 0xc7, 0xb3, 0x53, 0x42, 0x01, 0xcf, 0xb1, 0xcd, 0x0d
                ],
                point: [
                    0xf0, 0x79, 0xfc, 0xe7, 0x9a, 0x0e, 0xeb, 0x55, 0x38, 0x6d, 0xf9, 0x98, 0xbd, 0x45, 0x50, 0xc6, 0x7d, 0x04, 0xbf, 0x5c, 0xa2, 0x7b, 0xb1, 0xf2, 0x4d, 0x5a, 0x60, 0xb7, 0x78, 0x89, 0x7c, 0x22
                ],
            },
            TestVector {
                u: [
                    0xbd, 0x69, 0xb8, 0x25, 0x32, 0xb6, 0x94, 0x0f, 0xf2, 0x59, 0x0f, 0x67, 0x9b, 0xa9, 0xc7, 0x27, 0x1f, 0xe0, 0x1f, 0x7e, 0x9c, 0x8e, 0x36, 0xd6, 0xa5, 0xe2, 0x9d, 0x4e, 0x30, 0xa7, 0x35, 0x14
                ],
                point: [
                    0x8c, 0xbe, 0xa3, 0xa5, 0x7c, 0xd9, 0x7d, 0x81, 0x67, 0x2a, 0x71, 0x4c, 0x34, 0x2f, 0x79, 0x4c, 0xfe, 0xd3, 0xd3, 0x3d, 0x36, 0xf5, 0x84, 0x61, 0x97, 0x6a, 0xcb, 0xd7, 0xea, 0xae, 0x97, 0xb5
                ],
            },
            TestVector {
                u: [
                    0xbc, 0x50, 0x98, 0x42, 0x55, 0xd6, 0xaf, 0xbe, 0x9e, 0xf9, 0x28, 0x48, 0xed, 0x5a, 0xc0, 0x08, 0x62, 0xc2, 0xfa, 0x7b, 0x2f, 0xec, 0xbc, 0xb6, 0x4b, 0x69, 0x68, 0x91, 0x2a, 0x63, 0x81, 0x0e
                ],
                point: [
                    0x8f, 0x4b, 0x9c, 0xdc, 0xde, 0x69, 0xcf, 0x0a, 0x43, 0xad, 0x46, 0x8c, 0x9e, 0x42, 0x03, 0x73, 0x7c, 0xd7, 0xb0, 0xad, 0x58, 0x09, 0xd8, 0x72, 0xc3, 0x58, 0xda, 0xa5, 0x87, 0xa6, 0xca, 0x2d
                ],
            },
            TestVector {
                u: [
                    0x3d, 0xc1, 0x66, 0xd5, 0x6a, 0x1d, 0x62, 0xf5, 0xa8, 0xd7, 0x55, 0x1d, 0xb5, 0xfd, 0x93, 0x13, 0xe8, 0xc7, 0x20, 0x3d, 0x99, 0x6a, 0xf7, 0xd4, 0x77, 0x08, 0x37, 0x56, 0xd5, 0x9a, 0xf8, 0x0d
                ],
                point: [
                    0xad, 0x66, 0x64, 0xd8, 0x52, 0x6c, 0x29, 0xd0, 0xad, 0xfd, 0x57, 0x41, 0xf1, 0xc9, 0x64, 0x30, 0xb3, 0x71, 0x32, 0xe5, 0x44, 0x7f, 0x15, 0x84, 0x23, 0x4f, 0x51, 0x77, 0xc2, 0x1b, 0xc4, 0xb7
                ],
            },
            TestVector {
                u: [
                    0x05, 0xa7, 0x45, 0xf4, 0x5d, 0x7f, 0xf6, 0xdb, 0x10, 0xbc, 0x67, 0xfd, 0xf0, 0xf0, 0x3e, 0xbf, 0x81, 0x30, 0xab, 0x33, 0x36, 0x26, 0x97, 0xb0, 0xe4, 0xe4, 0xc7, 0x63, 0xcc, 0xb8, 0xf6, 0x36
                ],
                point: [
                    0xe1, 0x1b, 0xf6, 0x86, 0x4b, 0xe7, 0x9d, 0x11, 0x1e, 0x32, 0x86, 0xd3, 0xbb, 0x03, 0x9d, 0xcd, 0xcf, 0xcc, 0xad, 0x0e, 0x12, 0x1a, 0x3b, 0x60, 0xc5, 0x39, 0xcf, 0x74, 0x4c, 0x48, 0xa4, 0x88
                ],
            },
            TestVector {
                u: [
                    0x49, 0x5c, 0x22, 0x2f, 0x7f, 0xba, 0x1e, 0x31, 0xde, 0xfa, 0x3d, 0x5a, 0x57, 0xef, 0xc2, 0xe1, 0xe9, 0xb0, 0x1a, 0x03, 0x55, 0x87, 0xd5, 0xfb, 0x1a, 0x38, 0xe0, 0x1d, 0x94, 0x90, 0x3d, 0x3c
                ],
                point: [
                    0x6b, 0x46, 0x8c, 0x75, 0xaf, 0x38, 0xb6, 0x38, 0x6a, 0xd0, 0x83, 0xb2, 0xe0, 0x5c, 0xa9, 0xdb, 0xdb, 0xdb, 0x9e, 0x8a, 0xb1, 0x92, 0xde, 0x80, 0x49, 0x09, 0xf9, 0x13, 0x6e, 0x85, 0x0c, 0xaa
                ],
            },
            TestVector {
                u: [
                    0x3d, 0x0a, 0xd3, 0x36, 0x1f, 0xec, 0x09, 0x77, 0x90, 0xd9, 0xbe, 0x0e, 0x42, 0x98, 0x8d, 0x7d, 0x25, 0xc9, 0xa1, 0x38, 0xf4, 0x9b, 0x1a, 0x53, 0x7e, 0xdc, 0xf0, 0x4b, 0xe3, 0x4a, 0x98, 0x11
                ],
                point: [
                    0x42, 0x9c, 0xdc, 0xe4, 0x96, 0xa8, 0x96, 0xcf, 0x1e, 0xbf, 0x26, 0x72, 0x60, 0x26, 0x9c, 0x86, 0x6f, 0xd8, 0x38, 0x62, 0xcf, 0x02, 0x74, 0xc2, 0xa7, 0x94, 0x78, 0xc6, 0x12, 0xdc, 0x13, 0x9d
                ],
            },
            TestVector {
                u: [
                    0xa4, 0xaf, 0x9d, 0xb6, 0xd2, 0x7b, 0x50, 0x72, 0x83, 0x5f, 0x0c, 0x3e, 0x88, 0x39, 0x5e, 0xd7, 0xa4, 0x1b, 0x00, 0x52, 0xad, 0x80, 0x84, 0xa8, 0xb9, 0xda, 0x94, 0x8d, 0x32, 0x0d, 0xad, 0x16
                ],
                point: [
                    0xaf, 0xbd, 0xfb, 0xbc, 0x64, 0x6d, 0x2a, 0x56, 0x04, 0x02, 0x3c, 0x2b, 0x01, 0x56, 0x3a, 0xb2, 0x4d, 0x2f, 0x23, 0x36, 0x70, 0x6a, 0x86, 0x50, 0x84, 0x93, 0x8e, 0x6e, 0xcb, 0xb3, 0xc2, 0x2e
                ],
            },
            TestVector {
                u: [
                    0x4d, 0x54, 0x31, 0xe6, 0x43, 0x7d, 0x0b, 0x5b, 0xed, 0xbb, 0xcd, 0xaf, 0x34, 0x5b, 0x86, 0xc4, 0x12, 0x1f, 0xc0, 0x0f, 0xe7, 0xf2, 0x35, 0x73, 0x42, 0x76, 0xd3, 0x8d, 0x47, 0xf1, 0xe1, 0x11
                ],
                point: [
                    0x43, 0xcb, 0x90, 0x93, 0x91, 0xed, 0x2f, 0xae, 0x2f, 0x3f, 0x38, 0xe9, 0x59, 0x12, 0xdd, 0xa2, 0x38, 0xf2, 0x1f, 0xc9, 0x91, 0x17, 0x67, 0xc1, 0x5e, 0x58, 0xa3, 0xb8, 0xe0, 0xb0, 0x0a, 0x91
                ],
            },
        ]
}
