import rsa
import DES as des

'''Static class designed to take advantage of RSA encryption functions without
needing to utilize a constructor'''
class RSA:
    # class variables
    n = 0
    e = 0
    d = 0
    blockSize = 15
    cipherText = ""
    plainText = "Hello, my name is Bob. What is your name?"

    def setBlockSize(b):
        blockSize = b


    '''
    The functions below directly call only the necessary functions that need to
    be exposed for RSA encryption to work. A number of other functions are
    present in the file rsa.py that are required to actually make the
    encryption and decryption work, but don't need to be exposed in this file.
    '''


    def keyGen(magnitude):
        RSA.n, RSA.e, RSA.d = rsa.newKey(10 ** magnitude, 10 ** (magnitude + 1), 50)

    def encrypt(message = plainText):
        RSA.plainText = message
        RSA.cipherText = rsa.encrypt(message, RSA.n, RSA.e, RSA.blockSize)

    def decrypt():
        # initial decryption
        newPlainText = rsa.decrypt(RSA.cipherText, RSA.n, RSA.d, RSA.blockSize)
        decrypted = ""
        lengths = [len(RSA.plainText), len(newPlainText)]
        # use the lengths of the original plaintext and the new plaintext
        #  to determin how long the fully decrypted text should be, then
        #  trim off the excess characters (if necessary) and return the result
        if lengths[0] < lengths[1]:
            decrypted = newPlainText[:lengths[0]]
        return decrypted

class DES:
    keyBase = b"blahblah"
    keys = []
    data = b"Please encrypt my data"
    cipher = ""

    def keyGen(keyInput = keyBase):
        '''Takes a bytestring and converts it into a key.'''
        DES.keys = des.generateKey(keyInput)

    def encrypt():
        DES.cipher = crypt(keys, block, 'E')

    def decrypt():
        return blockData(keys, DES.cipher, 'D')
