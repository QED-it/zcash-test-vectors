// From https://github.com/zcash-hackworks/zcash-test-vectors/ (orchard_empty_roots)

pub(crate) struct TestVector {
    pub(crate) empty_roots: [[u8; 32]; 33],
}

        let test_vector = TestVector {
            empty_roots: [
                [0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                [0xd1, 0xab, 0x25, 0x07, 0xc8, 0x09, 0xc2, 0x71, 0x3c, 0x00, 0x0f, 0x52, 0x5e, 0x9f, 0xbd, 0xcb, 0x06, 0xc9, 0x58, 0x38, 0x4e, 0x51, 0xb9, 0xcc, 0x7f, 0x79, 0x2d, 0xde, 0x6c, 0x97, 0xf4, 0x11],
                [0xc7, 0x41, 0x3f, 0x46, 0x14, 0xcd, 0x64, 0x04, 0x3a, 0xbb, 0xab, 0x7c, 0xc1, 0x09, 0x5c, 0x9b, 0xb1, 0x04, 0x23, 0x1c, 0xea, 0x89, 0xe2, 0xc3, 0xe0, 0xdf, 0x83, 0x76, 0x95, 0x56, 0xd0, 0x30],
                [0x21, 0x11, 0xfc, 0x39, 0x77, 0x53, 0xe5, 0xfd, 0x50, 0xec, 0x74, 0x81, 0x6d, 0xf2, 0x7d, 0x6a, 0xda, 0x7e, 0xd2, 0xa9, 0xac, 0x38, 0x16, 0xaa, 0xb2, 0x57, 0x3c, 0x8f, 0xac, 0x79, 0x42, 0x04],
                [0x80, 0x6a, 0xfb, 0xfe, 0xb4, 0x5c, 0x64, 0xd4, 0xf2, 0x38, 0x4c, 0x51, 0xef, 0xf3, 0x07, 0x64, 0xb8, 0x45, 0x99, 0xae, 0x56, 0xa7, 0xab, 0x3d, 0x4a, 0x46, 0xd9, 0xce, 0x3a, 0xea, 0xb4, 0x31],
                [0x87, 0x3e, 0x41, 0x57, 0xf2, 0xc0, 0xf0, 0xc6, 0x45, 0xe8, 0x99, 0x36, 0x00, 0x69, 0xfc, 0xc9, 0xd2, 0xed, 0x9b, 0xc1, 0x1b, 0xf5, 0x98, 0x27, 0xaf, 0x02, 0x30, 0xed, 0x52, 0xed, 0xab, 0x18],
                [0x27, 0xab, 0x13, 0x20, 0x95, 0x3a, 0xe1, 0xad, 0x70, 0xc8, 0xc1, 0x5a, 0x12, 0x53, 0xa0, 0xa8, 0x6f, 0xbc, 0x8a, 0x0a, 0xa3, 0x6a, 0x84, 0x20, 0x72, 0x93, 0xf8, 0xa4, 0x95, 0xff, 0xc4, 0x02],
                [0x4e, 0x14, 0x56, 0x3d, 0xf1, 0x91, 0xa2, 0xa6, 0x5b, 0x4b, 0x37, 0x11, 0x3b, 0x52, 0x30, 0x68, 0x05, 0x55, 0x05, 0x1b, 0x22, 0xd7, 0x4a, 0x8e, 0x1f, 0x1d, 0x70, 0x6f, 0x90, 0xf3, 0x13, 0x3b],
                [0xb3, 0xbb, 0xe4, 0xf9, 0x93, 0xd1, 0x8a, 0x0f, 0x4e, 0xb7, 0xf4, 0x17, 0x4b, 0x1d, 0x85, 0x55, 0xce, 0x33, 0x96, 0x85, 0x5d, 0x04, 0x67, 0x6f, 0x1c, 0xe4, 0xf0, 0x6d, 0xda, 0x07, 0x37, 0x1f],
                [0x4e, 0xf5, 0xbd, 0xe9, 0xc6, 0xf0, 0xd7, 0x6a, 0xeb, 0x9e, 0x27, 0xe9, 0x3f, 0xba, 0x28, 0xc6, 0x79, 0xdf, 0xcb, 0x99, 0x1c, 0xbc, 0xb8, 0x39, 0x5a, 0x2b, 0x57, 0x92, 0x4c, 0xbd, 0x17, 0x0e],
                [0xa3, 0xc0, 0x25, 0x68, 0xac, 0xeb, 0xf5, 0xca, 0x1e, 0xc3, 0x0d, 0x6a, 0x7d, 0x7c, 0xd2, 0x17, 0xa4, 0x7d, 0x6a, 0x1b, 0x83, 0x11, 0xbf, 0x94, 0x62, 0xa5, 0xf9, 0x39, 0xc6, 0xb7, 0x43, 0x07],
                [0x3e, 0xf9, 0xb3, 0x0b, 0xae, 0x61, 0x22, 0xda, 0x16, 0x05, 0xba, 0xd6, 0xec, 0x5d, 0x49, 0xb4, 0x1d, 0x4d, 0x40, 0xca, 0xa9, 0x6c, 0x1c, 0xf6, 0x30, 0x2b, 0x66, 0xc5, 0xd2, 0xd1, 0x0d, 0x39],
                [0x22, 0xae, 0x28, 0x00, 0xcb, 0x93, 0xab, 0xe6, 0x3b, 0x70, 0xc1, 0x72, 0xde, 0x70, 0x36, 0x2d, 0x98, 0x30, 0xe5, 0x38, 0x00, 0x39, 0x88, 0x84, 0xa7, 0xa6, 0x4f, 0xf6, 0x8e, 0xd9, 0x9e, 0x0b],
                [0x18, 0x71, 0x10, 0xd9, 0x26, 0x72, 0xc2, 0x4c, 0xed, 0xb0, 0x97, 0x9c, 0xdf, 0xc9, 0x17, 0xa6, 0x05, 0x3b, 0x31, 0x0d, 0x14, 0x5c, 0x03, 0x1c, 0x72, 0x92, 0xbb, 0x1d, 0x65, 0xb7, 0x66, 0x1b],
                [0x3f, 0x98, 0xad, 0xbe, 0x36, 0x4f, 0x14, 0x8b, 0x0c, 0xc2, 0x04, 0x2c, 0xaf, 0xc6, 0xbe, 0x11, 0x66, 0xfa, 0xe3, 0x90, 0x90, 0xab, 0x4b, 0x35, 0x4b, 0xfb, 0x62, 0x17, 0xb9, 0x64, 0x45, 0x3b],
                [0x63, 0xf8, 0xdb, 0xd1, 0x0d, 0xf9, 0x36, 0xf1, 0x73, 0x49, 0x73, 0xe0, 0xb3, 0xbd, 0x25, 0xf4, 0xed, 0x44, 0x05, 0x66, 0xc9, 0x23, 0x08, 0x59, 0x03, 0xf6, 0x96, 0xbc, 0x63, 0x47, 0xec, 0x0f],
                [0x21, 0x82, 0x16, 0x3e, 0xac, 0x40, 0x61, 0x88, 0x5a, 0x31, 0x35, 0x68, 0x14, 0x8d, 0xfa, 0xe5, 0x64, 0xe4, 0x78, 0x06, 0x6d, 0xcb, 0xe3, 0x89, 0xa0, 0xdd, 0xb1, 0xec, 0xb7, 0xf5, 0xdc, 0x34],
                [0xbd, 0x9d, 0xc0, 0x68, 0x19, 0x18, 0xa3, 0xf3, 0xf9, 0xcd, 0x1f, 0x9e, 0x06, 0xaa, 0x1a, 0xd6, 0x89, 0x27, 0xda, 0x63, 0xac, 0xc1, 0x3b, 0x92, 0xa2, 0x57, 0x8b, 0x27, 0x38, 0xa6, 0xd3, 0x31],
                [0xca, 0x2c, 0xed, 0x95, 0x3b, 0x7f, 0xb9, 0x5e, 0x3b, 0xa9, 0x86, 0x33, 0x3d, 0xa9, 0xe6, 0x9c, 0xd3, 0x55, 0x22, 0x3c, 0x92, 0x97, 0x31, 0x09, 0x4b, 0x6c, 0x21, 0x74, 0xc7, 0x63, 0x8d, 0x2e],
                [0x55, 0x35, 0x4b, 0x96, 0xb5, 0x6f, 0x9e, 0x45, 0xaa, 0xe1, 0xe0, 0x09, 0x4d, 0x71, 0xee, 0x24, 0x8d, 0xab, 0xf6, 0x68, 0x11, 0x77, 0x78, 0xbd, 0xc3, 0xc1, 0x9c, 0xa5, 0x33, 0x1a, 0x4e, 0x1a],
                [0x70, 0x97, 0xb0, 0x4c, 0x2a, 0xa0, 0x45, 0xa0, 0xde, 0xff, 0xca, 0xca, 0x41, 0xc5, 0xac, 0x92, 0xe6, 0x94, 0x46, 0x65, 0x78, 0xf5, 0x90, 0x9e, 0x72, 0xbb, 0x78, 0xd3, 0x33, 0x10, 0xf7, 0x05],
                [0xe8, 0x1d, 0x68, 0x21, 0xff, 0x81, 0x3b, 0xd4, 0x10, 0x86, 0x7a, 0x3f, 0x22, 0xe8, 0xe5, 0xcb, 0x7a, 0xc5, 0x59, 0x9a, 0x61, 0x0a, 0xf5, 0xc3, 0x54, 0xeb, 0x39, 0x28, 0x77, 0x36, 0x2e, 0x01],
                [0x15, 0x7d, 0xe8, 0x56, 0x7f, 0x7c, 0x49, 0x96, 0xb8, 0xc4, 0xfd, 0xc9, 0x49, 0x38, 0xfd, 0x80, 0x8c, 0x3b, 0x2a, 0x5c, 0xcb, 0x79, 0xd1, 0xa6, 0x38, 0x58, 0xad, 0xaa, 0x9a, 0x6d, 0xd8, 0x24],
                [0xfe, 0x1f, 0xce, 0x51, 0xcd, 0x61, 0x20, 0xc1, 0x2c, 0x12, 0x46, 0x95, 0xc4, 0xf9, 0x8b, 0x27, 0x59, 0x18, 0xfc, 0xea, 0xe6, 0xeb, 0x20, 0x98, 0x73, 0xed, 0x73, 0xfe, 0x73, 0x77, 0x5d, 0x0b],
                [0x1f, 0x91, 0x98, 0x29, 0x12, 0x01, 0x26, 0x69, 0xf7, 0x4d, 0x0c, 0xfa, 0x10, 0x30, 0xff, 0x37, 0xb1, 0x52, 0x32, 0x4e, 0x5b, 0x83, 0x46, 0xb3, 0x33, 0x5a, 0x0a, 0xae, 0xb6, 0x3a, 0x0a, 0x2d],
                [0x5d, 0xec, 0x15, 0xf5, 0x2a, 0xf1, 0x7d, 0xa3, 0x93, 0x13, 0x96, 0x18, 0x3c, 0xbb, 0xbf, 0xbe, 0xa7, 0xed, 0x95, 0x07, 0x14, 0x54, 0x0a, 0xec, 0x06, 0xc6, 0x45, 0xc7, 0x54, 0x97, 0x55, 0x22],
                [0xe8, 0xae, 0x2a, 0xd9, 0x1d, 0x46, 0x3b, 0xab, 0x75, 0xee, 0x94, 0x1d, 0x33, 0xcc, 0x58, 0x17, 0xb6, 0x13, 0xc6, 0x3c, 0xda, 0x94, 0x3a, 0x4c, 0x07, 0xf6, 0x00, 0x59, 0x1b, 0x08, 0x8a, 0x25],
                [0xd5, 0x3f, 0xde, 0xe3, 0x71, 0xce, 0xf5, 0x96, 0x76, 0x68, 0x23, 0xf4, 0xa5, 0x18, 0xa5, 0x83, 0xb1, 0x15, 0x82, 0x43, 0xaf, 0xe8, 0x97, 0x00, 0xf0, 0xda, 0x76, 0xda, 0x46, 0xd0, 0x06, 0x0f],
                [0x15, 0xd2, 0x44, 0x4c, 0xef, 0xe7, 0x91, 0x4c, 0x9a, 0x61, 0xe8, 0x29, 0xc7, 0x30, 0xec, 0xeb, 0x21, 0x62, 0x88, 0xfe, 0xe8, 0x25, 0xf6, 0xb3, 0xb6, 0x29, 0x8f, 0x6f, 0x6b, 0x6b, 0xd6, 0x2e],
                [0x4c, 0x57, 0xa6, 0x17, 0xa0, 0xaa, 0x10, 0xea, 0x7a, 0x83, 0xaa, 0x6b, 0x6b, 0x0e, 0xd6, 0x85, 0xb6, 0xa3, 0xd9, 0xe5, 0xb8, 0xfd, 0x14, 0xf5, 0x6c, 0xdc, 0x18, 0x02, 0x1b, 0x12, 0x25, 0x3f],
                [0x3f, 0xd4, 0x91, 0x5c, 0x19, 0xbd, 0x83, 0x1a, 0x79, 0x20, 0xbe, 0x55, 0xd9, 0x69, 0xb2, 0xac, 0x23, 0x35, 0x9e, 0x25, 0x59, 0xda, 0x77, 0xde, 0x23, 0x73, 0xf0, 0x6c, 0xa0, 0x14, 0xba, 0x27],
                [0x87, 0xd0, 0x63, 0xcd, 0x07, 0xee, 0x49, 0x44, 0x22, 0x2b, 0x77, 0x62, 0x84, 0x0e, 0xb9, 0x4c, 0x68, 0x8b, 0xec, 0x74, 0x3f, 0xa8, 0xbd, 0xf7, 0x71, 0x5c, 0x8f, 0xe2, 0x9f, 0x10, 0x4c, 0x2a],
                [0xae, 0x29, 0x35, 0xf1, 0xdf, 0xd8, 0xa2, 0x4a, 0xed, 0x7c, 0x70, 0xdf, 0x7d, 0xe3, 0xa6, 0x68, 0xeb, 0x7a, 0x49, 0xb1, 0x31, 0x98, 0x80, 0xdd, 0xe2, 0xbb, 0xd9, 0x03, 0x1a, 0xe5, 0xd8, 0x2f],
            ],
        };
