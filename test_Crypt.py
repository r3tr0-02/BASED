from base64 import b64encode, b64decode
import json

from Crypto.PublicKey import ECC
from Crypto.Protocol.DH import key_agreement
from Crypto.Hash import SHAKE128, SHA512
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Signature import eddsa
#import pysodium

#import rsa

import xeddsa
import secrets

from kyber import Kyber1024
#from dilithium import Dilithium2

# ! functions below may or may not be used
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

def kdf(x):
    return SHAKE128.new(x).read(32)

z_spk = gen_Z()
z_pqspk = gen_Z()
z = gen_Z()

# `* KEY GEN FOR Bob

# Curve Identity Key (IK)
b_id_key = ECC.generate(curve='ed25519')
# b_id_key_public = b_id_key.public_key().export_key(format='raw')
# b_id_key_public = xeddsa.ed25519_pub_to_curve25519_pub(b_id_key_public)
# b_id_key_private = xeddsa.seed_to_priv(b_id_key.seed)

#b_id_key = pysodium.crypto_scalarmult_curve25519()

b_id_key_public = b_id_key.public_key()
b_id_key_private = b_id_key

# Curve Signed PreKey (SPK)
b_spk_key = ECC.generate(curve='ed25519')
# b_spk_key_public = b_spk_key.public_key().export_key(format='raw')
# b_spk_key_public = xeddsa.ed25519_pub_to_curve25519_pub(b_spk_key_public)
# b_spk_key_private = xeddsa.seed_to_priv(b_spk_key.seed)
b_spk_key_public = b_spk_key.public_key()
b_spk_key_private = b_spk_key 

# Signature of SPK (Sig(SPK))
#b_sig_spk = xeddsa.ed25519_priv_sign(b_id_key_private, EncodeEC(b_spk_key_public), z_spk)
signer_b = eddsa.new(b_id_key_private, 'rfc8032')
b_sig_spk = signer_b.sign(SHA512.new(b_spk_key_public.export_key(format='DER')))
#print(EncodeEC(b_spk_key_public.export_key))

# PQ Signed PreKey (PQSPK)
b_pqspk_pkey, b_pqspk_skey = Kyber1024.keygen()

# Signature of PQ Signed PreKey (Sig(PQSPK))
#b_sig_pqspk = xeddsa.ed25519_priv_sign(b_id_key_private, EncodeKEM(b_pqspk_pkey), z_pqspk)
b_sig_pqspk = signer_b.sign(SHA512.new(b_pqspk_pkey))

# Curve One-Time Prekey (OPK)
b_opk_key = ECC.generate(curve='ed25519')
#b_opk_key_public = b_opk_key.public_key().export_key(format='raw')
#b_opk_key_public = xeddsa.ed25519_pub_to_curve25519_pub(b_opk_key_public)
#b_opk_key_private = xeddsa.seed_to_priv(b_opk_key.seed)
b_opk_key_public = b_opk_key.public_key()
b_opk_key_private = b_opk_key

# PQ One-Time PreKey (PQOPK)
b_pqopk_pkey, b_pqopk_skey = Kyber1024.keygen()

# Signature of PQ One-Time Prekey (Sig(PQOPK))
#b_sig_pqopk = xeddsa.ed25519_priv_sign(b_id_key_private, EncodeKEM(b_pqopk_pkey), z)
b_sig_pqopk = signer_b.sign(SHA512.new(b_pqopk_pkey))


# `* KEY GEN FOR Alice

z_spk = gen_Z()
z_pqspk = gen_Z()
z = gen_Z()

# Curve Identity Key (IK)
a_id_key = ECC.generate(curve='ed25519')
#a_id_key_public = a_id_key.public_key().export_key(format='raw')
#a_id_key_public = xeddsa.ed25519_pub_to_curve25519_pub(a_id_key_public)
#a_id_key_private = xeddsa.seed_to_priv(a_id_key.seed)
a_id_key_public = a_id_key.public_key()
a_id_key_private = a_id_key

# Curve Signed PreKey (SPK)
a_spk_key = ECC.generate(curve='ed25519')
#a_spk_key_public = a_spk_key.public_key().export_key(format='raw')
#a_spk_key_public = xeddsa.ed25519_pub_to_curve25519_pub(a_spk_key_public)
#a_spk_key_private = xeddsa.seed_to_priv(a_spk_key.seed)
a_spk_key_public = a_spk_key.public_key()
a_spk_key_private = a_spk_key

# Signature of SPK (Sig(SPK))
#a_sig_spk = xeddsa.ed25519_priv_sign(a_id_key_private, EncodeEC(a_spk_key_public), z_spk)
signer_a = eddsa.new(a_id_key_private, 'rfc8032')
a_sig_spk = signer_a.sign(SHA512.new(a_spk_key_public.export_key(format='DER')))

# PQ Signed PreKey (PQSPK)
a_pqspk_pkey, a_pqspk_skey = Kyber1024.keygen()

# Signature of PQ Signed PreKey (Sig(PQSPK))
#a_sig_pqspk = xeddsa.ed25519_priv_sign(a_id_key_private, EncodeKEM(a_pqspk_pkey), z_pqspk)
a_sig_pqspk = signer_a.sign(SHA512.new(a_pqspk_pkey))

# Curve One-Time Prekey (OPK)
a_opk_key = ECC.generate(curve='ed25519')
#a_opk_key_public = a_opk_key.public_key().export_key(format='raw')
#a_opk_key_public = xeddsa.ed25519_pub_to_curve25519_pub(a_opk_key_public)
#a_opk_key_private = xeddsa.seed_to_priv(a_opk_key.seed)
a_opk_key_public = a_opk_key.public_key()
a_opk_key_private = a_opk_key

# PQ One-Time PreKey (PQOPK)
a_pqopk_pkey, a_pqopk_skey = Kyber1024.keygen()

# Signature of PQ One-Time Prekey (Sig(PQOPK))
#a_sig_pqopk = xeddsa.ed25519_priv_sign(a_id_key_private, EncodeKEM(a_pqopk_pkey), z)
a_sig_pqopk = signer_a.sign(SHA512.new(a_pqopk_pkey))


# `* Alice retrieve key from Bob and perform calc

# Alice fetches [IK] b_id_key_public, [SPK] b_spk_key_public, Sig(SPK) b_sig_spk
# [PQOPK] b_pqopk_pkey, Sig(PQOPK) b_sig_pqopk
# [OPK] b_opk_key_public

verifier_a = eddsa.new(b_id_key_public, 'rfc8032')

try:
    #check = xeddsa.ed25519_verify(b_sig_spk, b_id_key_public, EncodeEC(b_spk_key_public))
    verifier_a.verify(SHA512.new(b_spk_key_public.export_key(format='DER')), b_sig_spk)

    #check = xeddsa.ed25519_verify(b_sig_pqspk, b_id_key_public, EncodeKEM(b_pqopk_pkey))
    verifier_a.verify(SHA512.new(b_pqspk_pkey), b_sig_pqspk)

    #check = xeddsa.ed25519_verify(b_sig_pqopk, b_id_key_public, EncodeKEM(b_pqopk_pkey))
    verifier_a.verify(SHA512.new(b_pqopk_pkey), b_sig_pqopk)
except ValueError:
    print("Keys are not authentic!")
else:
    print("Keys are authentic!")
    # Ephemeral Key (EP)
    a_ep_key = ECC.generate(curve='ed25519')
    a_ep_key_public = a_ep_key.public_key()
    a_ep_key_private = a_ep_key

    ct_pq_a, ss_pq_a = Kyber1024.enc(b_pqopk_pkey)

    dh_1 = key_agreement(static_priv=a_id_key_private, static_pub=b_spk_key_public, kdf=kdf)
    dh_2 = key_agreement(static_priv=a_ep_key_private, static_pub=b_id_key_public, kdf=kdf)
    dh_3 = key_agreement(static_priv=a_ep_key_private, static_pub=b_spk_key_public, kdf=kdf)
    dh_4 = key_agreement(static_priv=a_ep_key_private, static_pub=b_opk_key, kdf=kdf)

    sk_a = kdf(dh_1 + dh_2 + dh_3 + dh_4 + ss_pq_a)
    print("sk for Alice : ", sk_a)

    a_ep_key_private = ""
    dh_1 = b""
    dh_2 = b""
    dh_3 = b""
    dh_4 = b""

    ad = a_id_key_public.export_key(format='DER') + b_id_key_public.export_key(format='DER')
    header = ad
    
    cipher_a = AES.new(sk_a, AES.MODE_EAX)
    cipher_a.update(header)
    ct_a, tag_a = cipher_a.encrypt_and_digest(b'ct_from_a')

    json_k = [ 'nonce', 'header', 'ciphertext', 'tag' ]
    json_v = [ b64encode(x).decode('utf-8') for x in (cipher_a.nonce, header, ct_a, tag_a) ]
    result = json.dumps(dict(zip(json_k, json_v)))
    #print(result)

# `* Bob retrives key from Alice and perform calc

# Bob fetches [IK] a_id_key_public, [SPK] a_spk_key_public, Sig(SPK) a_sig_spk
# [PQOPK] a_pqopk_pkey, Sig(PQOPK) a_sig_pqopk
# [OPK] a_opk_key_public

verifier_b = eddsa.new(a_id_key_public, 'rfc8032')

try:
    #check = xeddsa.ed25519_verify(b_sig_spk, b_id_key_public, EncodeEC(b_spk_key_public))
    verifier_b.verify(SHA512.new(a_spk_key_public.export_key(format='DER')), a_sig_spk)
    
    #check = xeddsa.ed25519_verify(b_sig_pqspk, b_id_key_public, EncodeKEM(b_pqopk_pkey))
    verifier_b.verify(SHA512.new(a_pqspk_pkey), a_sig_pqspk)
    
    #check = xeddsa.ed25519_verify(b_sig_pqopk, b_id_key_public, EncodeKEM(b_pqopk_pkey))
    verifier_b.verify(SHA512.new(a_pqopk_pkey), a_sig_pqopk)
    
except ValueError:
    print("Keys are not authentic!")
else:
    print("Keys are authentic!")
    # Ephemeral Key (EP)
    b_ep_key = ECC.generate(curve='ed25519')
    b_ep_key_public = b_ep_key.public_key()
    b_ep_key_private = b_ep_key

    pt_pq_b = Kyber1024.dec(ct_pq_a, b_pqopk_skey)

    if ss_pq_a == pt_pq_b: print("pt == ss ok")
    else: print("not ok")

    dh_1 = key_agreement(static_priv=b_id_key_private, static_pub=a_spk_key_public, kdf=kdf)
    dh_2 = key_agreement(static_priv=b_ep_key_private, static_pub=a_id_key_public, kdf=kdf)
    dh_3 = key_agreement(static_priv=b_ep_key_private, static_pub=a_spk_key_public, kdf=kdf)
    dh_4 = key_agreement(static_priv=b_ep_key_private, static_pub=a_opk_key, kdf=kdf)

    print("dh_1 : ", dh_1)
    print("dh_2 : ", dh_2)
    print("dh_3 : ", dh_3)
    print("dh_4 : ", dh_4)

    print(dh_1 + dh_2 + dh_3 + dh_4 + pt_pq_b)

    sk_b = kdf(dh_1 + dh_2 + dh_3 + dh_4 + pt_pq_b)
    print("sk for Bob : ", sk_b)

    b_ep_key_private = ""
    dh_1 = b""
    dh_2 = b""
    dh_3 = b""
    dh_4 = b""

    ad = a_id_key_public.export_key(format='DER') + b_id_key_public.export_key(format='DER')
    header = ad
    
    try:
        b64 = json.loads(result)
        json_k = [ 'nonce', 'header', 'ciphertext', 'tag' ]
        jv = {k:b64decode(b64[k]) for k in json_k}

        cipher_b = AES.new(sk_b, AES.MODE_EAX, nonce=jv['nonce'])
        cipher_b.update(header)
        pt_a = cipher_b.decrypt_and_verify(jv['ciphertext'], jv['tag'])

        print(pt_a)
    except (ValueError, KeyError):
        print("Incorrect decryption!")