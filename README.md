# csc590_assn1
Implementation of symmetric and asymmetric cryptography algorithms for MSU CSC 590-002

To run on Windows: Load Idle (version 3.4), then load encryption_test.py.
To use RSA encryption, run the following commands in the interpreter:

```Python
RSA.genKeys(50)
RSA.encrypt(message) # message is optional
RSA.decrypt() # Outputs decrypted text
# To check if the decryption outputs the same as the original plaintext:
RSA.decrypt() == RSA.plainText
```
