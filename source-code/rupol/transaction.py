# RuPol: a dumb implementation of a draft ring confidential transaction scheme
#
# Use this code only for prototyping
# -- putting this code into production would be dumb
# -- assuming this code is secure would also be dumb

import dumb25519
import account

# protocol parameters
# TODO: make these not arbitrary
p1 = 3 # for n-ary representations
p2 = 3
R = 3 # ring size
beta = 2**64 - 1 # max amount

# witness for a spend
class Witness:
    d_ijk = None
    x_i = None
    a_in = None
    a_ij = None
    r_in = None
    r_out = None

    def __init__(self,d_ijk,x_i,a_in,a_ij,r_in,r_out):
        self.d_ijk = d_ijk
        self.x_i = x_i
        self.a_in = a_in
        self.a_ij = a_ij
        self.r_in = r_in
        self.r_out = r_out

class Transaction:
    tags = None
    accounts_ring = None
    accounts_out = None

    def __init__(self,tags,accounts_ring,accounts_out):
        self.tags = tags # tag for each input account
        self.accounts_ring = accounts_ring # ring of input and fake accounts
        self.accounts_out = accounts_out # output accounts

    def __str__(self):
        return str(self.tags) + str(self.accounts_ring) + str(self.accounts_out)

# compute the n-ary representation of an integer (lsb is index 0), and pad to a given size
def nary(i,n,pad=None):
    if i < 0 or n < 1:
        raise ArithmeticError
    if pad is not None and pad < 1:
        raise IndexError

    if i == 0:
        bits = [0]
    if i > 0:
        bits = []
        while i > 0:
            i,r = divmod(i,n)
            bits.append(r)
    
    if pad is None or pad <= len(bits):
        return bits
    while pad > len(bits):
        bits.append(0)
    return bits

def prepare_witness(withdrawal_keys,deposit_keys):
    a_in = [withdrawal_key.a for withdrawal_key in withdrawal_keys]
    a_out = [deposit_key.a for deposit_key in deposit_keys]
    r_in = [withdrawal_key.r for withdrawal_key in withdrawal_keys]
    r_out = [deposit_key.r for deposit_key in deposit_keys]

    if len(a_in) != len(r_in) or len(a_out) != len(r_out):
        raise IndexError

    max_i = len(a_in)
    max_j = len(nary(R,p1))
    max_k = p1

    d_ijk = []
    for i in range(max_i):
        d_ijk.append([])
        i_decomp = nary(i,p1,max_j)

        for j in range(max_j):
            d_ijk[i].append([])

            for k in range(max_k):
                if i_decomp[j] == k:
                    d_ijk[i][j].append(dumb25519.Scalar(1))
                else:
                    d_ijk[i][j].append(dumb25519.Scalar(0))

    max_i = len(a_out)
    max_j = len(nary(beta,p2))

    a_ij = []
    for i in range(max_i):
        a_ij.append([dumb25519.Scalar(a) for a in nary(a_out[i].to_int(),p2,max_j)])

    return Witness(d_ijk,[withdrawal_key.x for withdrawal_key in withdrawal_keys],a_in,a_ij,r_in,r_out)

def spend(withdrawal_keys,deposit_keys,tx,mu):
    witness = prepare_witness(withdrawal_keys,deposit_keys)
    witness_list = [witness.d_ijk,witness.x_i,witness.a_in,witness.a_ij,witness.r_in,witness.r_out] # this is so we can flatten for commitment

    t = dumb25519.random_scalar()
    C = dumb25519.pedersen_commit(dumb25519.flatten(witness_list),t)

    s = dumb25519.hash_to_scalar(str(C)+str(tx)+str(mu))
