# NewHope
A shared library implemented using the post-quantum cryptography scheme known currently as "NewHope",
and published in the NIST page [1]. The files "newhope.*" contain the interface available to the user,
basically:
    -KeyGen: Generation of keys.
    -Encrypt: encrypt the message given the public key.
    -Decrypt: decrypt the message using the private key.

All other files are internal to the scheme workings.

[1] https://newhopecrypto.org/