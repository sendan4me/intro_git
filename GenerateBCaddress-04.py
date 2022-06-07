import os
import ecdsa
import hashlib
import base58
import binascii

# generate public key form private key
private_key = os.urandom(32)
public_key = ecdsa.SigningKey.from_string( private_key, curve=ecdsa.SECP256k1 ).verifying_key.to_string()
print( "*public key=", binascii.hexlify( public_key) )

# add prefix(0x04) as "uncompressed public key"
prefix_and_pubkey = b"\x04" + public_key
print( "*prefix and public key=", binascii.hexlify(prefix_and_pubkey) )

# generate 160-bit hash by double hash(sha256 and ripemd160)
ripemd160 = hashlib.new( 'ripemd160' )
ripemd160.update( hashlib.sha256( prefix_and_pubkey ).digest() )
hash160 = ripemd160.digest()
print( "*hash160=", binascii.hexlify( hash160 ) )

# add version byte (0x00) : means "pubkey_hash"
pubkey_hash = b"\x00" + hash160

# hash pubkey_hash two times with sha256
double_sha256 = hashlib.sha256( hashlib.sha256( pubkey_hash ).digest() ).digest()
print( "*double hash key=", binascii.hexlify( double_sha256 ) )

# extract 4 bytes-checksum from the top of double_sha256
checksum = double_sha256[:4]

# add checksum to the bottom of row address
row_address = pubkey_hash + checksum
print( "*row address( before base58 )=",binascii.hexlify( row_address ))

# create blockchain address by base58 encoding
address = base58.b58encode( row_address )
print( "*blockchain address=",address.decode() )