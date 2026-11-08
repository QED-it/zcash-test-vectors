// From https://github.com/zcash/zcash-test-vectors/blob/master/zcash_test_vectors/zip_0244.py

pub(crate) struct TestVector {
    pub(crate) tx: &'static [u8],
    pub(crate) txid: [u8; 32],
    pub(crate) auth_digest: [u8; 32],
    pub(crate) amounts: &'static [i64],
    pub(crate) script_pubkeys: &'static [&'static [u8]],
    pub(crate) transparent_input: Option<u32>,
    pub(crate) sighash_shielded: [u8; 32],
    pub(crate) sighash_all: Option<[u8; 32]>,
    pub(crate) sighash_none: Option<[u8; 32]>,
    pub(crate) sighash_single: Option<[u8; 32]>,
    pub(crate) sighash_all_anyone: Option<[u8; 32]>,
    pub(crate) sighash_none_anyone: Option<[u8; 32]>,
    pub(crate) sighash_single_anyone: Option<[u8; 32]>,
}

pub(crate) const TEST_VECTORS: &[TestVector] = &[];
