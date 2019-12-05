import sys, os, itertools, json

from playcrypt.tools import *
from playcrypt.ideal.block_cipher import *
from playcrypt.ideal.message_authentication_code import *
from playcrypt.games.game_ufcma import GameUFCMA
from playcrypt.simulator.ufcma_sim import UFCMASim
from playcrypt.games.game_lr import GameLR
from playcrypt.simulator.lr_sim import LRSim
from playcrypt.games.game_int_ctxt import GameINTCTXT
from playcrypt.simulator.ctxt_sim import CTXTSim
from playcrypt.ideal.function_family import *

"""
Problem 2 [50 points]

Let SE_1=(K_1,Enc_1,Dec_1) be any symmetric encryption scheme. 
Let T_1:{0,1}^k x {0,1}^* -> {0,1}^l be any MAC.
	
Then, let SE=(K,E,D) be a symmetric encryption scheme and 
T: {0,1}^{2k} x {0,1}^* -> {0,1}^l be a MAC, with algorithms described below. 
"""

def Enc_1(K,M):
    M = split(M,n_bytes)
    R = random_string(n_bytes)
    C = [R]
    W = []
    for i in range(len(M)):
        x = int_to_string((2**(i+1) - 1) << (n_bytes*8 - (i+1)))
        W.append(xor_strings(R, x))
        C.append(E(K, xor_strings(M[i], W[i])))
    return join(C)


def Enc(K,M):
    K = split(K, k_bytes)
    C = Enc_1(K[0], M)
    return K[1]+C


def Tag_1(K,M):

    if len(M) <= 0 or len(M)*8 > n*(2**n) or len(M) % n_bytes != 0:
        return None

    # M[1]...M[m] <- M; M[m+1] <- <m>
    M = split(M, n_bytes)
    m = len(M)
    M = [None] + M + [int_to_string(m, n_bytes)]

    # C[0] <- 0^n
    C = ["\x00" * n_bytes]

    # For i = 1,...,m+1 do C[i] <- E(K, C[i-1] xor M[i])
    for i in range(1, m + 2):
        C += [E(K, xor_strings(C[i - 1], M[i]))]

    # T <- C[m+1]; Return T
    return C[m + 1]


def Tag(K,M):
    K = split(K,k_bytes)
    T = Tag_1(K[1],M)
    return K[0]+T



"""
2.1(a,b) [25 points] Define the adversary A1. It should run A2 at some point, where A2 is given the simulated oracle to use in place of its regular LR oracle
"""
def A1(lr, A2):
    """
    You must fill in this method. We will define variables k, n, k_bytes,
    n_bytes, Tag, Enc, Enc_1, and Tag_1 for you.

    Construct an oracle LrSim which A1 can run that perfectly simulates the LR oracle which A2 would have gotten in the
    IND-CPA game. More specifically, LrSim should take M_0, M_1 as input and return E(K1 || K2, M_b).
    K1 and b should be consistent with the values used in LR. Note that since this oracle is run by A1, it cannot
    directly make use of K1 or b, but it may use the LR oracle.

    Your A1 will need to run A2 at some point, with LrSim as the oracle.

    :param lr: This is the oracle supplied by the game.
    :param A2: This is the adversary for SE
    :return: 1 for right game, 0 for left game.
    """
    def LrSim(M0, M1):
        pass

    pass




"""
2.2(a,b) [25 points] Define the adversary B1. It should run B2 at some point, where B2 is given the simulated oracle to use in place of its regular Tag oracle.
"""
def B1(tag, B2):
    """
    You must fill in this method. We will define variables k, n, k_bytes, n_bytes, Tag, Enc, Enc_1, and Tag_1 for you.

    Construct an oracle TagSim which B1 can run that perfectly simulates the Tag oracle which B2 would have gotten in
    the UFCMA_Tag game. More specifically, TagSim should take M as input and return T(K1 || K2 , M). K2 should be
    consistent with the value used in Tag. Note that since this oracle is run by B1, it cannot directly make use of K2,
    but it may use the Tag oracle.
    """ 
    def TagSim(M):
        pass

    pass 


"""
==============================================================================================
The following lines are used to test your code, and should not be modified.
==============================================================================================
"""

def V_1(K, M, t):
    if Tag_1(K, M) == t:
        return 1
    else:
        return 0


def A2(lr):
    a = '\x00' * n_bytes
    b = '\x80' + '\x00'* (n_bytes - 1)
    c = '\xC0'+'\x00'*(n_bytes - 1)
    C = lr(a + a, b + c)
    C = split(C, k_bytes)
    K2 = C[0]
    C = join(C[1:])
    C = split(C, n_bytes)

    if (C[1] == C[2]):
        return 1
    else:
        return 0


def B2(tag):
    v0 = ("\x00" * n_bytes)
    v1 = ("\x00" * (n_bytes - 1) + "\x01")
    v3 = ("\x00" * (n_bytes - 1) + "\x03")
    
    x0 = v0
    T0 = tag(x0)
    T0 = split(T0, k_bytes)
    K1 = T0[0]
    T0 = join(T0[1:])

    x1 = v0 + v1 + T0
    T1 = tag(x1)
    T2 = split(T1, k_bytes)
    T2 = join(T2[1:])
    x2 = v0 + v3 + T2
    return x2, T1



if __name__ == '__main__':    
    k = 64
    n = 64
    k_bytes = k//8
    n_bytes = n//8

    EE = BlockCipher(k_bytes, n_bytes)
    E = EE.encrypt
    E_I = EE.decrypt
    G = FunctionFamily(k_bytes, n_bytes, n_bytes).evaluate
 
    g = GameLR(1, Enc_1, k_bytes)
    a1 = partial(A1, A2=A2)
    s = LRSim(g, a1)
    
    print ("When k=64, n=64:")
    print ("The advantage of your adversary A1 is ~" + str(s.compute_advantage(10000)))

    g = GameUFCMA(2, Tag_1, V_1, k_bytes)
    b1 = partial(B1, B2=B2)
    s = UFCMASim(g, b1)
    
    print ("When k=64, n=64:")
    print ("The advantage of your adversary B1 is ~" + str(s.compute_advantage(10000)))
