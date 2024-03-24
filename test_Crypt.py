import base64

from Crypto.PublicKey import ECC
from Crypto.Protocol.DH import key_agreement
from Crypto.Hash import SHAKE128, SHA512
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Signature import eddsa
import nacl

import xeddsa
import secrets

from kyber import Kyber1024
#from dilithium import Dilithium2

def EncodeEC(x):
    return base64.b64encode(x)

def DecodeEC(x):
    return base64.b64decode(x)

def EncodeKEM(x):
    return base64.b64encode(x)

def DecodeKEM(x):
    return base64.b64decode(x)

def gen_Z():
    return secrets.token_bytes(64)

z_spk = gen_Z()
z_pqspk = gen_Z()
z = gen_Z()

# `* KEY GEN FOR Bob

# Curve Identity Key (IK)
b_id_key = ECC.generate(curve='ed25519')
b_id_key_public = b_id_key.public_key().export_key(format='raw')
b_id_key_public = xeddsa.ed25519_pub_to_curve25519_pub(b_id_key_public)
b_id_key_private = xeddsa.seed_to_priv(b_id_key.seed)

# Curve Signed PreKey (SPK)
b_spk_key = ECC.generate(curve='ed25519')
b_spk_key_public = b_spk_key.public_key().export_key(format='raw')
b_spk_key_public = xeddsa.ed25519_pub_to_curve25519_pub(b_spk_key_public)
b_spk_key_private = xeddsa.seed_to_priv(b_spk_key.seed)

# Signature of SPK (Sig(SPK))
b_sig_spk = xeddsa.ed25519_priv_sign(b_id_key_private, EncodeEC(b_spk_key_public), z_spk)
print(EncodeEC(b_spk_key_public))

# PQ Signed PreKey (PQSPK)
b_pqspk_pkey, b_pqspk_skey = Kyber1024.keygen()

# Signature of PQ Signed PreKey (Sig(PQSPK))
b_sig_pqspk = xeddsa.ed25519_priv_sign(b_id_key_private, EncodeKEM(b_pqspk_pkey), z_pqspk)

# Curve One-Time Prekey (OPK)
b_opk_key = ECC.generate(curve='ed25519')
b_opk_key_public = b_opk_key.public_key().export_key(format='raw')
b_opk_key_public = xeddsa.ed25519_pub_to_curve25519_pub(b_opk_key_public)
b_opk_key_private = xeddsa.seed_to_priv(b_opk_key.seed)

# PQ One-Time PreKey (PQOPK)
b_pqopk_pkey, b_pqopk_skey = Kyber1024.keygen()

# Signature of PQ One-Time Prekey (Sig(PQOPK))
b_sig_pqopk = xeddsa.ed25519_priv_sign(b_id_key_private, EncodeKEM(b_pqopk_pkey), z)


# `* KEY GEN FOR Alice

z_spk = gen_Z()
z_pqspk = gen_Z()
z = gen_Z()

# Curve Identity Key (IK)
a_id_key = ECC.generate(curve='ed25519')
a_id_key_public = a_id_key.public_key().export_key(format='raw')
a_id_key_public = xeddsa.ed25519_pub_to_curve25519_pub(a_id_key_public)
a_id_key_private = xeddsa.seed_to_priv(a_id_key.seed)

# Curve Signed PreKey (SPK)
a_spk_key = ECC.generate(curve='ed25519')
a_spk_key_public = a_spk_key.public_key().export_key(format='raw')
a_spk_key_public = xeddsa.ed25519_pub_to_curve25519_pub(a_spk_key_public)
a_spk_key_private = xeddsa.seed_to_priv(a_spk_key.seed)

# Signature of SPK (Sig(SPK))
a_sig_spk = xeddsa.ed25519_priv_sign(a_id_key_private, EncodeEC(a_spk_key_public), z_spk)

# PQ Signed PreKey (PQSPK)
a_pqspk_pkey, a_pqspk_skey = Kyber1024.keygen()

# Signature of PQ Signed PreKey (Sig(PQSPK))
a_sig_pqspk = xeddsa.ed25519_priv_sign(a_id_key_private, EncodeKEM(a_pqspk_pkey), z_pqspk)

# Curve One-Time Prekey (OPK)
a_opk_key = ECC.generate(curve='ed25519')
a_opk_key_public = a_opk_key.public_key().export_key(format='raw')
a_opk_key_public = xeddsa.ed25519_pub_to_curve25519_pub(a_opk_key_public)
a_opk_key_private = xeddsa.seed_to_priv(a_opk_key.seed)

# PQ One-Time PreKey (PQOPK)
a_pqopk_pkey, a_pqopk_skey = Kyber1024.keygen()

# Signature of PQ One-Time Prekey (Sig(PQOPK))
a_sig_pqopk = xeddsa.ed25519_priv_sign(a_id_key_private, EncodeKEM(a_pqopk_pkey), z)


# `* Alice retrieve key from Bob and perform calc

check = xeddsa.ed25519_verify(b_sig_spk, b_id_key_public, EncodeEC(b_spk_key_public))
print(check)
check = xeddsa.ed25519_verify(b_sig_pqspk, b_id_key_public, EncodeKEM(b_pqopk_pkey))
print(check)
check = xeddsa.ed25519_verify(b_sig_pqopk, b_id_key_public, EncodeKEM(b_pqopk_pkey))
print(check)

if check:
    print("Keys are verified!")
else:
    print("Keys are not verified! These keys cannot be trusted!")
