# generate a RSA key pair
`openssl genrsa -out private.pem 2048`

# export the public key as a JWK
parse public key info from private PEM key file:

`openssl rsa -in private.pem -pubout`

now to convert the public key from PEM format to JWK, put the output of the command above into a converter like https://russelldavies.github.io/jwk-creator/
providing also:
 - the key usage (which is `use`)
 - the algorithm used to sign JWT
 - the kid used to identify the key pair when signing the JWT

# sign JWTs
ReadFromPem class parses the RSA private key from the provided PEM file then sign tokens using SHA256withRSA algorithm.