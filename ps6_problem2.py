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
Problem 2

Let SE_1=(K_1,Enc_1,Dec_1) be any symmetric encryption scheme. 
Let T_1:{0,1}^k x {0,1}^* -> {0,1}^n be any MAC.
	
Then, let SE=(K,E,D) be a symmetric encryption scheme and 
T: {0,1}^{2k} x {0,1}^* -> {0,1}^{n+k} be a MAC, with algorithms described below. 

Finally, let AE=(K_a,E_a,D_a) be the AE scheme which combines SE and T in a Encrypt-then-MAC generic composition, but using the same key for both encryption and tag generation. These algorithms are described in full detail below.  
"""

def Enc_1(K,M):
    M = split(M,n_bytes)
    R = random_string(n_bytes)
    C = [R]
    P = [0]
    for i in range(0,len(M)):
        x = G(K, add_int_to_string(C[0], i+1, n_bytes))
        C.append(xor_strings(M[i], x))
    return join(C)

def Dec_1(K,C):
    C = split(C,n_bytes)
    M = []
    for i in range(1,len(C)):
        x = G(K, add_int_to_string(C[0], i, n_bytes))
        M.append(xor_strings(C[i], x))
    return join(M)   
    

def Enc(K,M):
    K = split(K, k_bytes)
    C = Enc_1(K[0], M)
    return K[1]+C


def Dec(K,C):
    C = split(C, n_bytes)
    K_1 = C[0]
    C = join(C[1:])
    
    K = split(K, k_bytes)
    M = Dec_1(K[0], C)
    return M
    

def Tag(K,M):
    K = split(K,k_bytes)
    T = Tag_1(K[1],M)
    return K[0]+T


def AEnc(K,M):
    C = Enc(K, M)
    T = Tag(K, C)
    return C+T


def ADec(K,C):
    C = split(C, n_bytes)
    t = join(C[-2:])
    C = join(C[:-2])
    M = Dec(K, C)
    T = Tag(K, C)
    if T == t:
        return M
    else:
        return None


    
"""
[25 points] Show that AE is not IND-CPA secure by presenting an O(t_E+n+k) time adversary A_1 making one query with Adv^ind-cpa_AE(A_1)=1.
"""
def A1(lr):
    """
    You must fill in this method. We will define variables k, n, k_bytes,
    n_bytes, AEnc, ADec, Tag, Enc, Dec, Enc_1, Dec_1, and Tag_1 for you.

    :param lr: This is the oracle supplied by the game. 
    :return: 1 for right game, 0 for left game. 
    """

    pass
    




"""
[25 points] Show that AE is not INT-CTXT secure by presenting an O(t_E+n+k) time adversary A_2 making one query with Adv^int-ctxt_AE(A_2)=1.
"""
def A2(enc):
    """You must fill in this method. We will define variables k, n, k_bytes,
    n_bytes, AEnc, ADec, Tag, Enc, Dec, Enc_1, Dec_1, and Tag_1 for you.

    :param tag: This is the oracle supplied by the game.
    """

    pass
    


"""
==============================================================================================
The following lines are used to test your code, and should not be modified.
==============================================================================================
"""

if __name__ == '__main__':    
    k = 64
    n = 64
    k_bytes = k//8
    n_bytes = n//8
 
    G = FunctionFamily(k_bytes, n_bytes, n_bytes).evaluate
    Mac = MAC(k_bytes, n_bytes)
    Tag_1 = Mac.tag
 
    g = GameLR(1, AEnc, 2*k_bytes)
    s = LRSim(g, A1)
    
    print ("When k=64, n=64:")
    print ("The advantage of your adversary A1 is ~" + str(s.compute_advantage()))

    g = GameINTCTXT(AEnc, ADec, 2*k_bytes)
    s = CTXTSim(g, A2)

    print ("When k=64, n=64:")
    print ("The advantage of your adversary A2 is ~" + str(s.compute_advantage()))

    k = 128
    n = 128
    k_bytes = k//8
    n_bytes = n//8

    G = FunctionFamily(k_bytes, n_bytes, n_bytes).evaluate
    Mac = MAC(k_bytes, n_bytes)
    Tag_1 = Mac.tag
 
    g = GameLR(1, AEnc, 2*k_bytes)
    s = LRSim(g, A1)

    print ("When k=128, n=128:")
    print ("The advantage of your adversary A1 is ~" + str(s.compute_advantage()))

    g = GameINTCTXT(AEnc, ADec, 2*k_bytes)
    s = CTXTSim(g, A2)

    print ("When k=128, n=128:")
    print ("The advantage of your adversary A2 is ~" + str(s.compute_advantage()))
