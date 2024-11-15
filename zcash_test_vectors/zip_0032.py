from hashlib import blake2b

from .sapling.key_components import prf_expand
from .utils import i2leosp

from .hd_common import hardened
from .output import render_args, render_tv

class HardenedOnlyContext(object):
    def __init__(self, MKGDomain, CKDDomain):
        assert type(MKGDomain) == bytes
        assert len(MKGDomain) == 16
        assert type(CKDDomain) == bytes
        assert len(CKDDomain) == 1

        self.MKGDomain = MKGDomain
        self.CKDDomain = CKDDomain

def MKGh(Context, IKM):
    assert type(Context) == HardenedOnlyContext

    digest = blake2b(person=Context.MKGDomain)
    digest.update(IKM)
    I   = digest.digest()
    I_L = I[:32]
    I_R = I[32:]
    return (I_L, I_R)

def CKDh(Context, sk_par, c_par, i):
    assert type(Context) == HardenedOnlyContext
    assert 0x80000000 <= i and i <= 0xFFFFFFFF

    I   = prf_expand(c_par, Context.CKDDomain + sk_par + i2leosp(32, i))
    I_L = I[:32]
    I_R = I[32:]
    return (I_L, I_R)

class ArbitraryKey(object):
    Arbitrary = HardenedOnlyContext(b'ZcashArbitraryKD', b'\xAB')

    def __init__(self, IKM, path, sk, chaincode):
        self.IKM = IKM
        self.path = path
        self.sk = sk
        self.chaincode = chaincode

    @classmethod
    def master(cls, ContextString, S):
        length_ContextString = len(ContextString)
        length_S = len(S)

        assert length_ContextString <= 252
        assert 32 <= length_S <= 252

        IKM = bytes([length_ContextString]) + ContextString + bytes([length_S]) + S
        (sk, chaincode) = MKGh(cls.Arbitrary, IKM)
        return cls(IKM, [], sk, chaincode)

    def child(self, i):
        (sk_i, c_i) = CKDh(self.Arbitrary, self.sk, self.chaincode, i)
        return self.__class__(None, self.path + [i], sk_i, c_i)


def arbitrary_key_derivation_tvs():
    args = render_args()

    context_string = b'Zcash test vectors'
    seed = bytes(range(32))
    m = ArbitraryKey.master(context_string, seed)
    m_1h = m.child(hardened(1))
    m_1h_2h = m_1h.child(hardened(2))
    m_1h_2h_3h = m_1h_2h.child(hardened(3))

    # Derive a path matching Zcash mainnet account index 0.
    m_32h = m.child(hardened(32))
    m_32h_133h = m_32h.child(hardened(133))
    m_32h_133h_0h = m_32h_133h.child(hardened(0))

    keys = [m, m_1h, m_1h_2h, m_1h_2h_3h, m_32h, m_32h_133h, m_32h_133h_0h]

    test_vectors = [
        {
            'context_string': context_string,
            'seed': seed,
            'ikm':  k.IKM,
            'path': k.path,
            'sk' : k.sk,
            'c'  : k.chaincode
        }
        for k in keys
    ]

    render_tv(
        args,
        'zip_0032_arbitrary',
        (
            ('context_string', 'Vec<u8>'),
            ('seed', '[u8; 32]'),
            ('ikm',  'Option<Vec<u8>>'),
            ('path', 'Vec<u32>'),
            ('sk',  '[u8; 32]'),
            ('c',   '[u8; 32]'),
        ),
        test_vectors,
    )
