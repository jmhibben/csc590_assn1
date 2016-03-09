#variables and tables for multiplication for DES
data = b"Please encrypt my data"
datacopy = b"Please encrypt my data"
TheKey = b"blahblah"
keySize = 8
blockSize = 8
padding = b"x"
expansionTable = [
        31,  0,  1,  2,  3,  4,
         3,  4,  5,  6,  7,  8,
         7,  8,  9, 10, 11, 12,
        11, 12, 13, 14, 15, 16,
        15, 16, 17, 18, 19, 20,
        19, 20, 21, 22, 23, 24,
        23, 24, 25, 26, 27, 28,
        27, 28, 29, 30, 31,  0
    ]

sbox = [
        # S1
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
         0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
         4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
         15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],

        # S2
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
         3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
         0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
         13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],

        # S3
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
         13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
         13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
         1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],

        # S4
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
         13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
         10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
         3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],

        # S5
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
         14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
         4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
         11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],

        # S6
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
         10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
         9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
         4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],

        # S7
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
         13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
         1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
         6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],

        # S8
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
         1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
         7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
         2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
                ]
    
sboxOutputTable = [
        15, 6, 19, 20, 28, 11,
        27, 16, 0, 14, 22, 25,
        4, 17, 30, 9, 1, 7,
        23,13, 31, 26, 2, 8,
        18, 12, 29, 5, 21, 10,
        3, 24
    ]

rotationsTable = [
        1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
    ]

firstPermutation = [57, 49, 41, 33, 25, 17, 9,  1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7,
        56, 48, 40, 32, 24, 16, 8,  0,
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6
    ]


choice1 = [56, 48, 40, 32, 24, 16,  8,
          0, 57, 49, 41, 33, 25, 17,
          9,  1, 58, 50, 42, 34, 26,
         18, 10,  2, 59, 51, 43, 35,
         62, 54, 46, 38, 30, 22, 14,
          6, 61, 53, 45, 37, 29, 21,
         13,  5, 60, 52, 44, 36, 28,
         20, 12,  4, 27, 19, 11,  3
    ]
choice2 = [
        13, 16, 10, 23,  0,  4,
         2, 27, 14,  5, 20,  9,
        22, 18, 11,  3, 25,  7,
        15,  6, 26, 19, 12,  1,
        40, 51, 30, 36, 46, 54,
        29, 39, 50, 44, 32, 47,
        43, 48, 38, 55, 33, 52,
        45, 41, 49, 35, 28, 31
    ]
finalPermutation = [
        39,  7, 47, 15, 55, 23, 63, 31,
        38,  6, 46, 14, 54, 22, 62, 30,
        37,  5, 45, 13, 53, 21, 61, 29,
        36,  4, 44, 12, 52, 20, 60, 28,
        35,  3, 43, 11, 51, 19, 59, 27,
        34,  2, 42, 10, 50, 18, 58, 26,
        33,  1, 41,  9, 49, 17, 57, 25,
        32,  0, 40,  8, 48, 16, 56, 24
    ]
def checkKeyInput(keyinput):#checks validity of input value to generate key
    if len(keyinput) != 8:
        raise ValueError("Invalid key size. Key must be exactly 8 bytes long. Entered:", len(key))

def convertToBits(data):#turns data string into list of bits
    l = len(data) * 8
    bits = [0] * l
    pos = 0
    for ch in data:
        #print(ch, data)
        i = 7
        while i >= 0:
            if ch & (1 << i) != 0:
                bits[pos] = 1
            else:
                bits[pos] = 0
            pos += 1
            i -= 1

    return bits

def convertToString(data):
    finalString= []
    pos = 0
    c = 0
    while pos < len(data):
        c += data[pos] << (7 - (pos % 8))
        if (pos % 8) == 7:
            finalString.append(c)
            c = 0
        pos += 1
    return bytes(finalString)
    
def generateKey(keyinput):
    checkKeyInput(keyinput)
    key = convertToBits(keyinput)
    sk = generateSubKeys(key)
    return sk


def transform(table, block):
    return list(map(lambda x: block[x], table))
    
def generateSubKeys(key):
    sk = [ [0] * 48 ] * 16 #subkeys list
    i = 0
    L = []
    R = []
    L = key[:28]
    R = key[28:]
    while i < 16:
        j = 0
        # Perform circular left shifts
        while j < rotationsTable[i]:
            L.append(L[0])
            del L[0]
            
            R.append(R[0])
            del R[0]
            
            j += 1
            

            # Create one of the 16 subkeys
        sk[i] = transform(choice2, L + R)

        i += 1
        
    return sk

def blockData(sk, data, ED):
    if not data:
        return ''
    if len(data) % blockSize != 0:
        data += (blockSize - (len(data) % blockSize)) * padding
    i = 0
    dict = {}
    fBlock = []
    while i < len(data):
        block = convertToBits(data[i:i+8])
        pBlock = crypt(sk, block, ED)
        fBlock.append(convertToString(pBlock))
        i += 8
    finalBlock = bytes.fromhex('').join(fBlock)
    if ED == 'D':
        finalBlock = finalBlock.decode("utf-8")
        if len(finalBlock) != len(datacopy):
            finalBlock = finalBlock[:len(datacopy)-len(data)]
    return finalBlock

def crypt(sk, block, ED):
    block = transform(firstPermutation, block)
    L = block[:32]
    R = block[32:]
    if ED == 'E':
        it = 0
        itchange = 1
    if ED == 'D':
        it = 15
        itchange = -1
    i = 0
    while(i < 16):
        tR = R[:]
        R = transform(expansionTable, R)
        #XOR R and sk
        R = list(map(lambda x, y: x ^ y, R, sk[it]))
        B = [R[:6], R[6:12], R[12:18], R[18:24], R[24:30], R[30:36], R[36:42], R[42:]]#split for substitution
        #apply sboxes
        j = 0
        BRes = [0] * 32
        pos = 0
        while j < 8:
            m = (B[j][0] << 1) + B[j][5]
            n = (B[j][1] << 3) + (B[j][2] << 2) + (B[j][3] << 1) + B[j][4]
            x = sbox[j][(m << 4) + n]

            BRes[pos] = (x & 8) >> 3
            BRes[pos + 1] = (x & 4) >> 2
            BRes[pos + 2] = (x & 2) >> 1
            BRes[pos + 3] = x & 1

            pos += 4
            j += 1
        #transform result B
        R = transform(sboxOutputTable, BRes)
        #XOR with L
        R = list(map(lambda x, y: x ^ y, R, L))
        L = tR
        i += 1
        it += itchange
    final = transform(finalPermutation, R + L)
    return final

def main():
    print("Welcome to the DES demonstration")
    print("This is the raw data to be encrypted: ", data.decode("utf-8"))
    print("Starting encryption with key:", TheKey.decode("utf-8"))
    sk = generateKey(TheKey)
    crypted = blockData(sk, data, 'E')
    print("crypted:",crypted)
    decrypted = blockData(sk, crypted, 'D')
    print("decrypted:", decrypted)
          
main()

