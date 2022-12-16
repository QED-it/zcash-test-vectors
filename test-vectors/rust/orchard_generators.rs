// From https://github.com/zcash-hackworks/zcash-test-vectors/ (orchard_generators)

pub(crate) struct TestVector {
    pub(crate) skb: [u8; 32],
    pub(crate) nkb: [u8; 32],
    pub(crate) vcvb: [u8; 32],
    pub(crate) vcrb: [u8; 32],
    pub(crate) cmb: [u8; 32],
    pub(crate) cmq: [u8; 32],
    pub(crate) ivkb: [u8; 32],
    pub(crate) ivkq: [u8; 32],
    pub(crate) mcq: [u8; 32],
}

        let test_vector = TestVector {
            skb: [
                0x63, 0xc9, 0x75, 0xb8, 0x84, 0x72, 0x1a, 0x8d, 0x0c, 0xa1, 0x70, 0x7b, 0xe3, 0x0c, 0x7f, 0x0c, 0x5f, 0x44, 0x5f, 0x3e, 0x7c, 0x18, 0x8d, 0x3b, 0x06, 0xd6, 0xf1, 0x28, 0xb3, 0x23, 0x55, 0xb7
            ],
            nkb: [
                0x75, 0xca, 0x47, 0xe4, 0xa7, 0x6a, 0x6f, 0xd3, 0x9b, 0xdb, 0xb5, 0xcc, 0x92, 0xb1, 0x7e, 0x5e, 0xcf, 0xc9, 0xf4, 0xfa, 0x71, 0x55, 0x37, 0x2e, 0x8d, 0x19, 0xa8, 0x9c, 0x16, 0xaa, 0xe7, 0x25
            ],
            vcvb: [
                0x67, 0x43, 0xf9, 0x3a, 0x6e, 0xbd, 0xa7, 0x2a, 0x8c, 0x7c, 0x5a, 0x2b, 0x7f, 0xa3, 0x04, 0xfe, 0x32, 0xb2, 0x9b, 0x4f, 0x70, 0x6a, 0xa8, 0xf7, 0x42, 0x0f, 0x3d, 0x8e, 0x7a, 0x59, 0x70, 0x2f
            ],
            vcrb: [
                0x91, 0x5a, 0x3c, 0x88, 0x68, 0xc6, 0xc3, 0x0e, 0x2f, 0x80, 0x90, 0xee, 0x45, 0xd7, 0x6e, 0x40, 0x48, 0x20, 0x8d, 0xea, 0x5b, 0x23, 0x66, 0x4f, 0xbb, 0x09, 0xa4, 0x0f, 0x55, 0x44, 0xf4, 0x07
            ],
            cmb: [
                0x13, 0x6e, 0xfc, 0x0f, 0x48, 0x2c, 0x02, 0x2c, 0x7c, 0xa4, 0x14, 0xfc, 0x5c, 0xc5, 0x9e, 0x23, 0xf2, 0x3d, 0x6f, 0x93, 0xab, 0x9f, 0x23, 0xcd, 0x33, 0x45, 0xa9, 0x28, 0xc3, 0x06, 0xb2, 0xa6
            ],
            cmq: [
                0x5d, 0x74, 0xa8, 0x40, 0x09, 0xba, 0x0e, 0x32, 0x2a, 0xdd, 0x46, 0xfd, 0x5a, 0x0f, 0x96, 0xc5, 0x5d, 0xed, 0xb0, 0x79, 0xb4, 0xf2, 0x9f, 0xf7, 0x0d, 0xcd, 0xfb, 0x56, 0xa0, 0x07, 0x80, 0x97
            ],
            ivkb: [
                0x18, 0xa1, 0xf8, 0x5f, 0x6e, 0x48, 0x23, 0x98, 0xc7, 0xed, 0x1a, 0xd3, 0xe2, 0x7f, 0x95, 0x02, 0x48, 0x89, 0x80, 0x40, 0x0a, 0x29, 0x34, 0x16, 0x4e, 0x13, 0x70, 0x50, 0xcd, 0x2c, 0xa2, 0xa5
            ],
            ivkq: [
                0xf2, 0x82, 0x0f, 0x79, 0x92, 0x2f, 0xcb, 0x6b, 0x32, 0xa2, 0x28, 0x51, 0x24, 0xcc, 0x1b, 0x42, 0xfa, 0x41, 0xa2, 0x5a, 0xb8, 0x81, 0xcc, 0x7d, 0x11, 0xc8, 0xa9, 0x4a, 0xf1, 0x0c, 0xbc, 0x05
            ],
            mcq: [
                0xa0, 0xc6, 0x29, 0x7f, 0xf9, 0xc7, 0xb9, 0xf8, 0x70, 0x10, 0x8d, 0xc0, 0x55, 0xb9, 0xbe, 0xc9, 0x99, 0x0e, 0x89, 0xef, 0x5a, 0x36, 0x0f, 0xa0, 0xb9, 0x18, 0xa8, 0x63, 0x96, 0xd2, 0x16, 0x16
            ],
        };
