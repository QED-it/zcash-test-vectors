// From https://github.com/zcash-hackworks/zcash-test-vectors/ (orchard_poseidon)

pub(crate) struct TestVector {
    pub(crate) initial_state: [[u8; 32]; 3],
    pub(crate) final_state: [[u8; 32]; 3],
}

pub(crate) fn test_vectors() -> Vec<TestVector> {
    vec![
        TestVector {
            initial_state: [
                [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                [0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            ],
            final_state: [
                [0x56, 0xa4, 0xec, 0x4a, 0x02, 0xbc, 0xb1, 0xae, 0xa0, 0x42, 0xb6, 0xd0, 0x71, 0x9a, 0xe6, 0xf7, 0x0f, 0x24, 0x66, 0xf9, 0x64, 0xb3, 0xef, 0x94, 0x53, 0xb4, 0x64, 0x0b, 0xcd, 0x6a, 0x52, 0x2a],
                [0x2a, 0xb8, 0xe5, 0x28, 0x96, 0x3e, 0x2a, 0x01, 0xfe, 0xda, 0xd9, 0xbe, 0x7f, 0x2e, 0xd4, 0xdc, 0x12, 0x55, 0x3d, 0x34, 0xae, 0x7d, 0xff, 0x76, 0x30, 0xa4, 0x4a, 0x8b, 0x56, 0xd1, 0xc5, 0x13],
                [0xdd, 0x9d, 0x4e, 0xd3, 0xa1, 0x29, 0x90, 0x35, 0x7b, 0x2c, 0xa4, 0xbd, 0xe1, 0xdf, 0xcf, 0xf7, 0x1a, 0x56, 0x84, 0x79, 0x59, 0xcd, 0x6f, 0x25, 0x44, 0x65, 0x97, 0xc6, 0x68, 0xc8, 0x49, 0x0a],
            ],
        },
        TestVector {
            initial_state: [
                [0x5c, 0x7a, 0x8f, 0x73, 0xad, 0xfc, 0x70, 0xfb, 0x3f, 0x13, 0x94, 0x49, 0xac, 0x6b, 0x57, 0x07, 0x4c, 0x4d, 0x6e, 0x66, 0xb1, 0x64, 0x93, 0x9d, 0xaf, 0xfa, 0x2e, 0xf6, 0xee, 0x69, 0x21, 0x08],
                [0x1a, 0xdd, 0x86, 0xb3, 0xf2, 0xe1, 0xbd, 0xa6, 0x2a, 0x5d, 0x2e, 0x0e, 0x98, 0x2b, 0x77, 0xe6, 0xb0, 0xef, 0x9c, 0xa3, 0xf2, 0x49, 0x88, 0xc7, 0xb3, 0x53, 0x42, 0x01, 0xcf, 0xb1, 0xcd, 0x0d],
                [0xbd, 0x69, 0xb8, 0x25, 0x32, 0xb6, 0x94, 0x0f, 0xf2, 0x59, 0x0f, 0x67, 0x9b, 0xa9, 0xc7, 0x27, 0x1f, 0xe0, 0x1f, 0x7e, 0x9c, 0x8e, 0x36, 0xd6, 0xa5, 0xe2, 0x9d, 0x4e, 0x30, 0xa7, 0x35, 0x14],
            ],
            final_state: [
                [0xd0, 0x6e, 0x2f, 0x83, 0x38, 0x92, 0x8a, 0x7e, 0xe7, 0x38, 0x0c, 0x77, 0x92, 0x80, 0x87, 0xcd, 0xa2, 0xfd, 0x29, 0x61, 0xa1, 0x52, 0x69, 0x03, 0x7a, 0x22, 0xd6, 0xd1, 0x20, 0xae, 0xdd, 0x21],
                [0x29, 0x55, 0xa4, 0x5f, 0x41, 0x6f, 0x10, 0xd6, 0xbc, 0x79, 0xac, 0x94, 0xd0, 0xc0, 0x69, 0xc9, 0x49, 0xe5, 0xf4, 0xbd, 0x09, 0x48, 0x1e, 0x1f, 0x36, 0x8c, 0xb9, 0xb8, 0xee, 0x51, 0x14, 0x0d],
                [0x0d, 0x83, 0x76, 0xbb, 0xe9, 0xd6, 0x5d, 0x2b, 0x1e, 0x13, 0x6f, 0xb7, 0xd9, 0x82, 0xab, 0x87, 0xc5, 0x1c, 0x40, 0x30, 0x44, 0xbe, 0x5c, 0x79, 0x9d, 0x56, 0xbb, 0x68, 0xac, 0xf9, 0x5b, 0x10],
            ],
        },
        TestVector {
            initial_state: [
                [0xbc, 0x50, 0x98, 0x42, 0x55, 0xd6, 0xaf, 0xbe, 0x9e, 0xf9, 0x28, 0x48, 0xed, 0x5a, 0xc0, 0x08, 0x62, 0xc2, 0xfa, 0x7b, 0x2f, 0xec, 0xbc, 0xb6, 0x4b, 0x69, 0x68, 0x91, 0x2a, 0x63, 0x81, 0x0e],
                [0x3d, 0xc1, 0x66, 0xd5, 0x6a, 0x1d, 0x62, 0xf5, 0xa8, 0xd7, 0x55, 0x1d, 0xb5, 0xfd, 0x93, 0x13, 0xe8, 0xc7, 0x20, 0x3d, 0x99, 0x6a, 0xf7, 0xd4, 0x77, 0x08, 0x37, 0x56, 0xd5, 0x9a, 0xf8, 0x0d],
                [0x05, 0xa7, 0x45, 0xf4, 0x5d, 0x7f, 0xf6, 0xdb, 0x10, 0xbc, 0x67, 0xfd, 0xf0, 0xf0, 0x3e, 0xbf, 0x81, 0x30, 0xab, 0x33, 0x36, 0x26, 0x97, 0xb0, 0xe4, 0xe4, 0xc7, 0x63, 0xcc, 0xb8, 0xf6, 0x36],
            ],
            final_state: [
                [0x0b, 0x77, 0xec, 0x53, 0x07, 0x14, 0x5a, 0x0c, 0x05, 0x2d, 0xc7, 0xa9, 0xd6, 0xf9, 0x6a, 0xc3, 0x41, 0xae, 0x72, 0x64, 0x08, 0x32, 0xd5, 0x8e, 0x51, 0xeb, 0x92, 0xa4, 0x17, 0x80, 0x17, 0x12],
                [0x3b, 0x52, 0x3f, 0x44, 0xf0, 0x0e, 0x46, 0x3f, 0x8b, 0x0f, 0xd7, 0xd4, 0xfc, 0x0e, 0x28, 0x0c, 0xdb, 0xde, 0xb9, 0x27, 0xf1, 0x81, 0x68, 0x07, 0x7b, 0xb3, 0x62, 0xf2, 0x67, 0x5a, 0x2e, 0x18],
                [0x95, 0x7a, 0x97, 0x06, 0xff, 0xcc, 0x35, 0x15, 0x64, 0xae, 0x80, 0x2a, 0x99, 0x11, 0x31, 0x4c, 0x05, 0xe2, 0x3e, 0x22, 0xaf, 0xcf, 0x83, 0x40, 0x59, 0xdf, 0x80, 0xfa, 0xc1, 0x05, 0x76, 0x26],
            ],
        },
        TestVector {
            initial_state: [
                [0x49, 0x5c, 0x22, 0x2f, 0x7f, 0xba, 0x1e, 0x31, 0xde, 0xfa, 0x3d, 0x5a, 0x57, 0xef, 0xc2, 0xe1, 0xe9, 0xb0, 0x1a, 0x03, 0x55, 0x87, 0xd5, 0xfb, 0x1a, 0x38, 0xe0, 0x1d, 0x94, 0x90, 0x3d, 0x3c],
                [0x3d, 0x0a, 0xd3, 0x36, 0x1f, 0xec, 0x09, 0x77, 0x90, 0xd9, 0xbe, 0x0e, 0x42, 0x98, 0x8d, 0x7d, 0x25, 0xc9, 0xa1, 0x38, 0xf4, 0x9b, 0x1a, 0x53, 0x7e, 0xdc, 0xf0, 0x4b, 0xe3, 0x4a, 0x98, 0x11],
                [0xa4, 0xaf, 0x9d, 0xb6, 0xd2, 0x7b, 0x50, 0x72, 0x83, 0x5f, 0x0c, 0x3e, 0x88, 0x39, 0x5e, 0xd7, 0xa4, 0x1b, 0x00, 0x52, 0xad, 0x80, 0x84, 0xa8, 0xb9, 0xda, 0x94, 0x8d, 0x32, 0x0d, 0xad, 0x16],
            ],
            final_state: [
                [0x67, 0x80, 0x08, 0x3f, 0x7f, 0x82, 0xcb, 0x42, 0x54, 0xe7, 0xb6, 0x6f, 0x4b, 0x83, 0x84, 0x6a, 0xc9, 0x77, 0x3f, 0xb9, 0xc3, 0x9c, 0x6e, 0xc9, 0x81, 0x8b, 0x06, 0x22, 0x23, 0x09, 0x55, 0x2a],
                [0xa5, 0xf9, 0xa5, 0x7e, 0x2c, 0x40, 0xb1, 0x58, 0xd8, 0x16, 0x53, 0x43, 0xe6, 0x02, 0x65, 0x2c, 0x3e, 0xfc, 0x0b, 0x64, 0xdd, 0xca, 0xee, 0xe5, 0xce, 0x3d, 0x95, 0x1f, 0xd5, 0x9f, 0x50, 0x08],
                [0xdc, 0xa4, 0x64, 0x36, 0x12, 0x7c, 0x47, 0x7e, 0x83, 0x95, 0x0f, 0xa0, 0x7c, 0xc6, 0x8a, 0x56, 0x6e, 0x54, 0x18, 0x55, 0xad, 0xc2, 0x68, 0x52, 0x97, 0x87, 0x35, 0x24, 0x88, 0x92, 0x1e, 0x3b],
            ],
        },
        TestVector {
            initial_state: [
                [0x4d, 0x54, 0x31, 0xe6, 0x43, 0x7d, 0x0b, 0x5b, 0xed, 0xbb, 0xcd, 0xaf, 0x34, 0x5b, 0x86, 0xc4, 0x12, 0x1f, 0xc0, 0x0f, 0xe7, 0xf2, 0x35, 0x73, 0x42, 0x76, 0xd3, 0x8d, 0x47, 0xf1, 0xe1, 0x11],
                [0xdd, 0x0c, 0x7a, 0x1d, 0x81, 0x1c, 0x7d, 0x9c, 0xd4, 0x6d, 0x37, 0x7b, 0x3f, 0xde, 0xab, 0x3f, 0xb6, 0x79, 0xf3, 0xdc, 0x60, 0x1d, 0x00, 0x82, 0x85, 0xed, 0xcb, 0xda, 0xe6, 0x9c, 0xe8, 0x3c],
                [0x19, 0xe4, 0xaa, 0xc0, 0x35, 0x90, 0x17, 0xec, 0x85, 0xa1, 0x83, 0xd2, 0x20, 0x53, 0xdb, 0x33, 0xf7, 0x34, 0x76, 0xf2, 0x1a, 0x48, 0x2e, 0xc9, 0x37, 0x83, 0x65, 0xc8, 0xf7, 0x39, 0x3c, 0x14],
            ],
            final_state: [
                [0x89, 0x99, 0x8e, 0x5e, 0x0f, 0xa1, 0x95, 0x2a, 0x40, 0xb8, 0xb5, 0x2b, 0x62, 0xd9, 0x45, 0x70, 0xa4, 0x9a, 0x7d, 0x91, 0xdd, 0x22, 0x6d, 0x69, 0x2b, 0xc9, 0xb1, 0xa6, 0x13, 0xc9, 0x08, 0x30],
                [0xd0, 0xee, 0x44, 0xd9, 0xa9, 0x0d, 0x90, 0x79, 0xef, 0xfb, 0x24, 0x86, 0xd3, 0xd8, 0x4d, 0x1a, 0x18, 0x4e, 0xdf, 0x14, 0x97, 0x0b, 0xac, 0x36, 0xc7, 0x48, 0x04, 0xc7, 0xff, 0xbe, 0xe5, 0x0b],
                [0x04, 0x81, 0x45, 0xa6, 0x61, 0xce, 0x78, 0x7c, 0x7e, 0x12, 0x2a, 0xc6, 0x44, 0x7e, 0x9b, 0xa3, 0x93, 0xd3, 0x67, 0xac, 0x05, 0x4f, 0xaa, 0xc5, 0xb7, 0xb5, 0xf7, 0x19, 0x2b, 0x2f, 0xde, 0x21],
            ],
        },
        TestVector {
            initial_state: [
                [0xe2, 0x88, 0x53, 0x15, 0xeb, 0x46, 0x71, 0x09, 0x8b, 0x79, 0x53, 0x5e, 0x79, 0x0f, 0xe5, 0x3e, 0x29, 0xfe, 0xf2, 0xb3, 0x76, 0x66, 0x97, 0xac, 0x32, 0xb4, 0xf4, 0x73, 0xf4, 0x68, 0xa0, 0x08],
                [0xe6, 0x23, 0x89, 0xfc, 0x16, 0x57, 0xe0, 0xde, 0xf0, 0xb6, 0x32, 0xc6, 0xae, 0x25, 0xf9, 0xf7, 0x83, 0xb2, 0x7d, 0xb5, 0x9a, 0x4a, 0x15, 0x3d, 0x88, 0x2d, 0x2b, 0x21, 0x03, 0x59, 0x65, 0x15],
                [0xeb, 0x94, 0x94, 0xc6, 0xd2, 0x27, 0xe2, 0x16, 0x3b, 0x46, 0x99, 0xd9, 0x91, 0xf4, 0x33, 0xbf, 0x94, 0x86, 0xa7, 0xaf, 0xcf, 0x4a, 0x0d, 0x9c, 0x73, 0x1e, 0x98, 0x5d, 0x99, 0x58, 0x9c, 0x0b],
            ],
            final_state: [
                [0xce, 0x2d, 0x1f, 0x8d, 0x67, 0x7f, 0xfb, 0xfd, 0x73, 0xb2, 0x35, 0xe8, 0xc6, 0x87, 0xfb, 0x42, 0x18, 0x7f, 0x78, 0x81, 0xc3, 0xce, 0x9c, 0x79, 0x4f, 0x2b, 0xd4, 0x61, 0x40, 0xf7, 0xcc, 0x2a],
                [0xaf, 0x82, 0x92, 0x39, 0xb6, 0xd5, 0x5d, 0x5f, 0x43, 0xec, 0x6f, 0x32, 0xb8, 0x4a, 0x2a, 0x01, 0x1e, 0x64, 0xc5, 0x74, 0x73, 0x9f, 0x87, 0xcb, 0x47, 0xdc, 0x70, 0x23, 0x83, 0xfa, 0x5a, 0x34],
                [0x03, 0xd1, 0x08, 0x5b, 0x21, 0x4c, 0x69, 0xb8, 0xbf, 0xe8, 0x91, 0x02, 0xbd, 0x61, 0x7e, 0xce, 0x0c, 0x54, 0x00, 0x17, 0x96, 0x40, 0x41, 0x05, 0xc5, 0x33, 0x30, 0xd2, 0x49, 0x58, 0x1d, 0x0f],
            ],
        },
        TestVector {
            initial_state: [
                [0xb7, 0x38, 0xe8, 0xaa, 0x0a, 0x15, 0x26, 0xa5, 0xbd, 0xef, 0x61, 0x31, 0x20, 0x37, 0x2e, 0x83, 0x1a, 0x20, 0xda, 0x8a, 0xba, 0x18, 0xd1, 0xdb, 0xeb, 0xbc, 0x86, 0x2d, 0xed, 0x42, 0x43, 0x1e],
                [0x91, 0x47, 0x69, 0x30, 0xe3, 0x38, 0x5c, 0xd3, 0xe3, 0x37, 0x9e, 0x38, 0x53, 0xd9, 0x34, 0x67, 0xe0, 0x01, 0xaf, 0xa2, 0xfb, 0x8d, 0xc3, 0x43, 0x6d, 0x75, 0xa4, 0xa6, 0xf2, 0x65, 0x72, 0x10],
                [0x4b, 0x19, 0x22, 0x32, 0xec, 0xb9, 0xf0, 0xc0, 0x24, 0x11, 0xe5, 0x25, 0x96, 0xbc, 0x5e, 0x90, 0x45, 0x7e, 0x74, 0x59, 0x39, 0xff, 0xed, 0xbd, 0x12, 0x86, 0x3c, 0xe7, 0x1a, 0x02, 0xaf, 0x11],
            ],
            final_state: [
                [0x5f, 0xcc, 0xd8, 0x7d, 0x2f, 0x66, 0x7b, 0x9e, 0xe3, 0x88, 0xf3, 0x4c, 0x1c, 0x71, 0x06, 0x87, 0x12, 0x7b, 0xff, 0x5b, 0x02, 0x21, 0xfd, 0x8a, 0x52, 0x94, 0x88, 0x66, 0x91, 0x57, 0x94, 0x2b],
                [0x89, 0x62, 0xb5, 0x80, 0x30, 0xaa, 0x63, 0x52, 0xd9, 0x90, 0xf3, 0xb9, 0x00, 0x1c, 0xcb, 0xe8, 0x8a, 0x56, 0x27, 0x58, 0x1b, 0xbf, 0xb9, 0x01, 0xac, 0x4a, 0x6a, 0xed, 0xfa, 0xe5, 0xc6, 0x34],
                [0x7c, 0x0b, 0x76, 0x59, 0xf2, 0x4c, 0x98, 0xaf, 0x31, 0x0e, 0x3e, 0x8d, 0x82, 0xb5, 0xf3, 0x99, 0x43, 0x3c, 0xdd, 0xa5, 0x8f, 0x48, 0xd9, 0xef, 0x8d, 0xd0, 0xca, 0x86, 0x42, 0x72, 0xda, 0x3f],
            ],
        },
        TestVector {
            initial_state: [
                [0x7b, 0x41, 0x7a, 0xdb, 0x63, 0xb3, 0x71, 0x22, 0xa5, 0xbf, 0x62, 0xd2, 0x6f, 0x1e, 0x7f, 0x26, 0x8f, 0xb8, 0x6b, 0x12, 0xb5, 0x6d, 0xa9, 0xc3, 0x82, 0x85, 0x7d, 0xee, 0xcc, 0x40, 0xa9, 0x0d],
                [0x5e, 0x29, 0x35, 0x39, 0x71, 0xb3, 0x49, 0x94, 0xb6, 0x21, 0xb0, 0xb2, 0x61, 0xae, 0xb3, 0x78, 0x6d, 0xd9, 0x84, 0xd5, 0x67, 0xdb, 0x28, 0x57, 0xb9, 0x27, 0xb7, 0xfa, 0xe2, 0xdb, 0x58, 0x31],
                [0x05, 0x41, 0x5d, 0x46, 0x42, 0x78, 0x9d, 0x38, 0xf5, 0x0b, 0x8d, 0xbc, 0xc1, 0x29, 0xca, 0xb3, 0xd1, 0x7d, 0x19, 0xf3, 0x35, 0x5b, 0xcf, 0x73, 0xce, 0xcb, 0x8c, 0xb8, 0xa5, 0xda, 0x01, 0x30],
            ],
            final_state: [
                [0x9e, 0xe1, 0xad, 0xdc, 0x6f, 0x64, 0xda, 0xb6, 0xac, 0xdc, 0xea, 0xec, 0xc1, 0xfb, 0xbc, 0x8a, 0x32, 0x45, 0x8e, 0x49, 0xc1, 0x9e, 0x79, 0x85, 0x56, 0xc6, 0x4b, 0x59, 0x8b, 0xa6, 0xff, 0x14],
                [0x42, 0xcc, 0x10, 0x36, 0x4f, 0xd6, 0x59, 0xc3, 0xcc, 0x77, 0x25, 0x84, 0xdb, 0x91, 0xc4, 0x9a, 0x38, 0x67, 0x2b, 0x69, 0x24, 0x93, 0xb9, 0x07, 0x5f, 0x16, 0x53, 0xca, 0x1f, 0xae, 0x1c, 0x33],
                [0xff, 0x41, 0xf3, 0x51, 0x80, 0x14, 0x56, 0xc4, 0x96, 0x0b, 0x39, 0x3a, 0xff, 0xa8, 0x62, 0x13, 0xa7, 0xea, 0xc0, 0x6c, 0x66, 0x21, 0x3b, 0x45, 0xc3, 0xb5, 0x0e, 0xc6, 0x48, 0xd6, 0x7d, 0x0d],
            ],
        },
        TestVector {
            initial_state: [
                [0x71, 0x52, 0xf1, 0x39, 0x36, 0xa2, 0x70, 0x57, 0x26, 0x70, 0xdc, 0x82, 0xd3, 0x90, 0x26, 0xc6, 0xcb, 0x4c, 0xd4, 0xb0, 0xf7, 0xf5, 0xaa, 0x2a, 0x4f, 0x5a, 0x53, 0x41, 0xec, 0x5d, 0xd7, 0x15],
                [0x40, 0x6f, 0x2f, 0xdd, 0x2a, 0xfa, 0x73, 0x3f, 0x5f, 0x64, 0x1c, 0x8c, 0x21, 0x86, 0x2a, 0x1b, 0xaf, 0xce, 0x26, 0x09, 0xd9, 0xee, 0xcf, 0xa1, 0x58, 0xcf, 0xb5, 0xcd, 0x79, 0xf8, 0x80, 0x08],
                [0xe2, 0x15, 0xdc, 0x7d, 0x96, 0x57, 0xba, 0xd3, 0xfb, 0x88, 0xb0, 0x1e, 0x99, 0x38, 0x44, 0x54, 0x36, 0x24, 0xc2, 0x5f, 0xa9, 0x59, 0xcc, 0x97, 0x48, 0x9c, 0xe7, 0x57, 0x45, 0x82, 0x4b, 0x37],
            ],
            final_state: [
                [0x63, 0x09, 0x15, 0xd7, 0xd8, 0x25, 0xeb, 0x74, 0x37, 0xb0, 0xe4, 0x6e, 0x37, 0x28, 0x6a, 0x88, 0xb3, 0x89, 0xdc, 0x69, 0x85, 0x93, 0x07, 0x11, 0x6d, 0x34, 0x7b, 0x98, 0xca, 0x14, 0x5c, 0x31],
                [0xaa, 0x58, 0x1b, 0xae, 0xe9, 0x4f, 0xb5, 0x46, 0xa7, 0x61, 0xf1, 0x7a, 0x5d, 0x6e, 0xaa, 0x70, 0x29, 0x52, 0x78, 0x42, 0xf3, 0x1c, 0x39, 0x87, 0xb8, 0x68, 0xed, 0x7d, 0xaf, 0xfd, 0xb5, 0x34],
                [0x7d, 0xc1, 0x17, 0xb3, 0x39, 0x1a, 0xab, 0x85, 0xde, 0x9f, 0x42, 0x4d, 0xb6, 0x65, 0x1e, 0x00, 0x45, 0xab, 0x79, 0x98, 0xf2, 0x8e, 0x54, 0x10, 0x15, 0x35, 0x90, 0x61, 0x99, 0xce, 0x1f, 0x1a],
            ],
        },
        TestVector {
            initial_state: [
                [0x86, 0x8c, 0x53, 0x23, 0x9c, 0xfb, 0xdf, 0x73, 0xca, 0xec, 0x65, 0x60, 0x40, 0x37, 0x31, 0x4f, 0xaa, 0xce, 0xb5, 0x62, 0x18, 0xc6, 0xbd, 0x30, 0xf8, 0x37, 0x4a, 0xc1, 0x33, 0x86, 0x79, 0x3f],
                [0x21, 0xa9, 0xfb, 0x80, 0xad, 0x03, 0xbc, 0x0c, 0xda, 0x4a, 0x44, 0x94, 0x6c, 0x00, 0xe1, 0xb1, 0xa1, 0xdf, 0x0e, 0x5b, 0x87, 0xb5, 0xbe, 0xce, 0x47, 0x7a, 0x70, 0x96, 0x49, 0xe9, 0x50, 0x06],
                [0x04, 0x91, 0x39, 0x48, 0x25, 0x64, 0xf1, 0x85, 0xc7, 0x90, 0x0e, 0x83, 0xc7, 0x38, 0x07, 0x0a, 0xf6, 0x55, 0x6d, 0xf6, 0xed, 0x4b, 0x4d, 0xdd, 0x3d, 0x9a, 0x69, 0xf5, 0x33, 0x57, 0xd7, 0x36],
            ],
            final_state: [
                [0x6a, 0x5a, 0x19, 0x19, 0xa4, 0x49, 0xa5, 0xe0, 0x29, 0x71, 0x1f, 0x48, 0x8a, 0xdb, 0xd6, 0xb0, 0x3e, 0x5c, 0x92, 0x7b, 0x6f, 0x9d, 0x9d, 0x35, 0xc5, 0xb3, 0xcc, 0xeb, 0x76, 0x60, 0x52, 0x03],
                [0x80, 0x47, 0x5b, 0x46, 0x89, 0x59, 0x61, 0x47, 0xab, 0x2a, 0xdf, 0x01, 0x73, 0xdb, 0x28, 0x9b, 0x3a, 0x26, 0xa1, 0x04, 0x84, 0x21, 0x73, 0xe8, 0x8b, 0xdb, 0xfe, 0xc0, 0x4a, 0x28, 0x67, 0x1b],
                [0x1e, 0xf3, 0xc8, 0xd0, 0xf5, 0x44, 0x44, 0xf5, 0x55, 0xb1, 0x5f, 0x7b, 0xc9, 0xfa, 0x4f, 0xfa, 0x0f, 0x56, 0x7c, 0x0f, 0x19, 0xac, 0x7d, 0x0f, 0xf9, 0x44, 0xfd, 0x36, 0x42, 0x6e, 0x32, 0x3a],
            ],
        },
        TestVector {
            initial_state: [
                [0x7d, 0x4f, 0x5c, 0xcb, 0x01, 0x64, 0x3c, 0x31, 0xdb, 0x84, 0x5e, 0xec, 0xd5, 0xd6, 0x3d, 0xc1, 0x6a, 0x95, 0xe3, 0x02, 0x5b, 0x97, 0x92, 0xff, 0xf7, 0xf2, 0x44, 0xfc, 0x71, 0x62, 0x69, 0x39],
                [0x26, 0xd6, 0x2e, 0x95, 0x96, 0xfa, 0x82, 0x5c, 0x6b, 0xf2, 0x1a, 0xff, 0x9e, 0x68, 0x62, 0x5a, 0x19, 0x24, 0x40, 0xea, 0x06, 0x82, 0x81, 0x23, 0xd9, 0x78, 0x84, 0x80, 0x6f, 0x15, 0xfa, 0x08],
                [0xd9, 0x52, 0x75, 0x4a, 0x23, 0x64, 0xb6, 0x66, 0xff, 0xc3, 0x0f, 0xdb, 0x01, 0x47, 0x86, 0xda, 0x3a, 0x61, 0x28, 0xae, 0xf7, 0x84, 0xa6, 0x46, 0x10, 0xa8, 0x9d, 0x1a, 0x70, 0x99, 0x21, 0x2d],
            ],
            final_state: [
                [0x1b, 0x4a, 0xc9, 0xbe, 0xf5, 0x6b, 0xdb, 0x6f, 0xb4, 0x2d, 0x3e, 0x3c, 0xd3, 0xa2, 0xac, 0x70, 0xa4, 0xc4, 0x0c, 0x42, 0x5b, 0x0b, 0xd6, 0x67, 0x9c, 0xa5, 0x7b, 0x30, 0x7e, 0xf1, 0xd4, 0x2f],
                [0x1a, 0x2e, 0xf4, 0x11, 0x94, 0xaa, 0xa2, 0x34, 0x32, 0xe0, 0x86, 0xed, 0x8a, 0xdb, 0xd1, 0xde, 0xec, 0x3c, 0x7c, 0xb3, 0x96, 0xde, 0x35, 0xba, 0xe9, 0x5a, 0xaf, 0x5a, 0x08, 0xa0, 0xec, 0x36],
                [0x68, 0xeb, 0x80, 0xc7, 0x3e, 0x2c, 0xcb, 0xde, 0xe1, 0xba, 0x71, 0x24, 0x77, 0x61, 0xd5, 0xb5, 0xec, 0xc6, 0x20, 0xe6, 0xe4, 0x8e, 0x00, 0x3b, 0x02, 0x3d, 0x9f, 0x55, 0x61, 0x66, 0x2f, 0x20],
            ],
        },
    ]
}
