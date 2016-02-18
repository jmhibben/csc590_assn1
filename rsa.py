'''
Author: James Hibben
A simple python implementation of an RSA cryptographic algorithm, for
MSU CSC 590-002 in the Spring Semester of 2016.

This file was written in conjunction with Zach Gilmer for an assignment in
implementing both symmetric-key and public-key (asymmetric-key) algorithms.

This program is based on avalonalex's RSA.py project, found
at https://gist.github.com/avalonalex/2122098. Some parts are removed or edited
due to alternate library imports and alternate ways to deal with certain
functions. Additionally, some functions were restructured to run as inner
functions in cases where they were only called from one function.
'''

from fractions import gcd
from random import randint
from math import log
from copy import copy

def coPrime(a, b):
    """Determine if a and b are coprime; return false if gcd(a,b) is anything
       other than 1"""
    if gcd(a,b) != 1:
        return False
    return True

def modExp(a, d, n):
    '''returns (a ** d) mod n'''
    def int2baseTwo(x):
        '''
        Convert x from positive integer to base-2.
        Returns list of bits in reverse order.
        '''
        assert x >= 0
        bitInverse = []
        while x != 0:
            bitInverse.append(x & 1)
            x >>= 1
        return bitInverse

    assert d >= 0
    assert n >= 0
    base2D = int2baseTwo(d)
    base2DLength = len(base2D)
    modArray = []
    result = 1
    for i in range(1, base2DLength + 1):
        if i == 1:
            modArray.append(a % n)
        else:
            modArray.append((modArray[i - 2] ** 2) % n)
    for i in range(0, base2DLength):
        if base2D[i] == 1:
            result *= base2D[i] * modArray[i]
    return result % n

def millerRabinTest(n, k):
    '''
    Miller-Rabin pseudo-prime test.
    Test is a fast approximation for a prime with good accuracy.
    Returning True: most likely a prime
    Returning False: definitely a composite
    k -> used to determine accuracy
    '''
    # go ahead and define function(s) here; the actual Miller-Rabin test is
    #   after the functions
    def extractTwos(m):
        '''
        Strict: m is non-negative.
        Counts the number of 0-bits there are at the end of bin(m), which can
        represented as (2 ** n) - 1.
        Returns a tuple (s, d) such that m = (2 ** i) * d.
        Only called within millerRabinTest
        '''
        assert m >= 0
        i = 0
        while m & (2 ** i) == 0:
            i += 1
        return i, m >> i

    def isComposite(a):
        x = modExp(a, d, n)
        if x == 1 or x == (n - 1):
            return None
        else:
            for i in range(1, s):
                x = modExp(x, 2, n)
                if x == 1:
                    return False
                elif x == (n - 1):
                    return None
            return False

    # millerRabinTest body
    assert n >= 1  # ensure that n is larger than 1
    assert k > 0  # ensure k is positive

    # 2 is a prime; show this
    if n == 2:
        return True

    # all even integers other than 2 are composites; show this
    if n % 2 == 0:
        return False

    extracted = extractTwos(n - 1)
    s = extracted[0]
    d = extracted[1]
    assert 2 ** s * d == n - 1

    for i in range(0, k):
        a = randint(2, n - 2)
        if isComposite(a) == False:
            return False
    return True  # reasonably certain that n is prime

def newKey(a, b, k):
    '''
    Try to find two pseudo primes ~ between a, b to generate the keys.
    Raises a ValueError if it cannot find one.
    '''
    # define inner functions
    def findPrime(a, b, k):
        '''
        Returns a pseudo-prime roughly between a, b (may be greater than b).
        Limit the number of attempts to find a pseudo-prime to
        10*ln(x)+3 (most likely thousands of attempts, so it shouldn't fail).
        If it can't find a prime, throw a ValueError to halt the program.
        '''
        x = randint(a, b)
        for i in range(0, int(10 * log(x) + 3)):
            if millerRabinTest(x, k):
                return x
            else:
                x += 1
        raise ValueError

    def extendedGCD(a, b):
        if a == 0:
            return b, 0, 1
        else:
            g, y, x = extendedGCD(b % a, a)
            return g, x - (b // a) * y, y

    def modMultInverse(e, totient):
        '''Modular Multiplicative Inverse function'''
        if coPrime(e, totient):
            combined = extendedGCD(e, totient)
            return combined[1] % totient
        else:
            return 0

    # newKey function body
    try:
        p = findPrime(a, b, k)
        while True:
            q = findPrime(a, b, k)
            if q != p:
                break
    except:
        raise ValueError

    n = p * q
    m = (p - 1) * (q - 1)

    while True:
        e = randint(1, m)
        if coPrime(e, m):
            break

    d = modMultInverse(e, m)
    return (n, e, d)

def encrypt(message, modN, e, blockSize):
    '''
    given a string message, public keys (e, n), and blockSize,
    encrypt using RSA algorithms
    '''
    # inner functions
    def string2numList(strn):
        '''convert an ASCII string to a list of integers'''
        return [ ord(char) for char in strn ]

    def numList2blocks(lst, blockSize):
        '''
        Takes a list of integers (range: 0-127) and combines them to be
        blockSize using base 256. If the length is not blockSize, then
        random integers will be generated to fill it.
        '''
        returnList = []
        toProcess = copy(lst)
        if len(toProcess) % blockSize != 0:
            for i in range(0, blockSize - len(toProcess) % blockSize):
                toProcess.append(randint(32, 126))
        for i in range(0, len(toProcess), blockSize):
            block = 0
            for j in range(0, blockSize):
                block += toProcess[i + j] << (8 * (blockSize - j - 1))
            returnList.append(block)
        return returnList

    numList = string2numList(message)
    numBlocks = numList2blocks(numList, blockSize)
    return [ modExp(blocks, e, modN) for blocks in numBlocks ]

def decrypt(cipher, modN, d, blockSize):
    '''reverses encryption'''
    # inner functions
    def numList2string(lst):
        '''convert a list of integers to a string based on their ASCII values'''
        return ''.join(map(chr, lst))

    def blocks2numList(blocks, blockSize):
        '''inverses numList2blocks'''
        toProcess = copy(blocks)
        returnList = []
        for numBlock in toProcess:
            inner = []
            for i in range(0, blockSize):
                inner.append(numBlock % 256)
                numBlock >>= 8
            inner.reverse()
            returnList.extend(inner)
        return returnList

    numBlocks = [ modExp(blocks, d, modN) for blocks in cipher ]
    numList = blocks2numList(numBlocks, blockSize)
    return numList2string(numList)
