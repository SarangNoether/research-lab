# RuPol: a dumb implementation of a draft ring confidential transaction scheme
#
# Use this code only for prototyping
# -- putting this code into production would be dumb
# -- assuming this code is secure would also be dumb

import dumb25519
import ecies
import stealth

# public curve points
G = dumb25519.G
H = dumb25519.H
T = dumb25519.T

class Account:
    pk = None
    co = None
    _ek = None
    _a = None
    _r = None

    def __init__(self,pk,co,_ek,_a,_r):
        self.pk = pk # account public key
        self.co = co # coin commitment
        self._ek = _ek # encrypted ephemeral key
        self._a = _a # encrypted amount
        self._r = _r # encrypted blinder

    def __str__(self):
        return [str(i) for i in [self.pk,self.co,self._ek,self._a,self._r]]

class WithdrawalKey:
    x = None
    a = None
    r = None
    tag = None

    def __init__(self,x,a,r,tag):
        self.x = x # offset private key
        self.a = a # amount
        self.r = r # blinder
        self.tag = tag # account tag

class DepositKey:
    a = None
    r = None

    def __init__(self,a,r):
        self.a = a # amount
        self.r = r # blinder

# generate a new one-time account
def gen_account(public_key,a):
    r = dumb25519.random_scalar()
    co = G*a + H*r

    ek = dumb25519.random_scalar()
    s = dumb25519.hash_to_scalar(str(public_key.tpk)+str(public_key.spk)+str(public_key.X)+str(ek))
    pk = public_key.X + H*s

    _ek = ecies.encrypt(public_key.tpk,str(pk)+str(co),str(ek))
    _a = ecies.encrypt(public_key.spk,str(pk)+str(co),str(a))
    _r = ecies.encrypt(public_key.spk,str(pk)+str(co),str(r))

    return Account(pk,co,_ek,_a,_r),DepositKey(a,r)

# recover the withdrawal key from a one-time account
def receive(private_key,account):
    ek = dumb25519.Scalar(int(ecies.decrypt(private_key.tsk,str(account.pk)+str(account.co),account._ek)))
    a = dumb25519.Scalar(int(ecies.decrypt(private_key.ssk,str(account.pk)+str(account.co),account._a)))
    r = dumb25519.Scalar(int(ecies.decrypt(private_key.ssk,str(account.pk)+str(account.co),account._r)))

    public_key = stealth.gen_public_key(private_key)
    s = dumb25519.hash_to_scalar(str(public_key.tpk)+str(public_key.spk)+str(public_key.X)+str(ek))

    if G*a + H*r != account.co:
        raise Exception('Bad account commitment!')
    if public_key.X + H*s != account.pk:
        raise Exception('Bad account public key!')

    xs = private_key.x+s
    return WithdrawalKey(xs,a,r,T*xs.invert())
