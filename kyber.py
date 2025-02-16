# -*- coding=utf-8 
import os
import time
import struct
import numpy as np
import hashlib
from hashlib import sha3_256, sha3_512, shake_128, shake_256
from polynomials import *
from modules import *
from ntt_helper import NTTHelperKyber
try:
    from aes256_ctr_drbg import AES256_CTR_DRBG
except ImportError as e:
    print("Error importing AES CTR DRBG. Have you tried installing requirements?")
    #print(f"ImportError: {e}\n")
    print("Kyber will work perfectly fine with system randomness")
    
    
DEFAULT_PARAMETERS = {
    "kyber_512" : {
        "n" : 256,
        "k" : 2,
        "q" : 3329,
        "eta_1" : 3,
        "eta_2" : 2,
        "du" : 10,
        "dv" : 4,
    },
    "kyber_768" : {
        "n" : 256,
        "k" : 3,
        "q" : 3329,
        "eta_1" : 2,
        "eta_2" : 2,
        "du" : 10,
        "dv" : 4,
    },
    "kyber_1024" : {
        "n" : 256,
        "k" : 4,
        "q" : 3329,
        "eta_1" : 2,
        "eta_2" : 2,
        "du" : 11,
        "dv" : 5,
    }
}

class Kyber:
    def __init__(self, parameter_set):
        self.n = parameter_set["n"]
        self.k = parameter_set["k"]
        self.q = parameter_set["q"]
        self.eta_1 = parameter_set["eta_1"]
        self.eta_2 = parameter_set["eta_2"]
        self.du = parameter_set["du"]
        self.dv = parameter_set["dv"]
        
        self.R = PolynomialRing(self.q, self.n, ntt_helper=NTTHelperKyber)
        self.M = Module(self.R)
        
        self.drbg = None
        self.random_bytes = os.urandom
        
    def set_drbg_seed(self, seed):
        """
        Setting the seed switches the entropy source
        from os.urandom to AES256 CTR DRBG
        
        Note: requires pycryptodome for AES impl.
        (Seemed overkill to code my own AES for Kyber)
        """
        self.drbg = AES256_CTR_DRBG(seed)
        self.random_bytes = self.drbg.random_bytes

    def reseed_drbg(self, seed):
        """
        Reseeds the DRBG, errors if a DRBG is not set.
        
        Note: requires pycryptodome for AES impl.
        (Seemed overkill to code my own AES for Kyber)
        """
        if self.drbg is None:
            raise Warning("Cannot reseed DRBG without first initialising. Try using `set_drbg_seed`")
        else:
            self.drbg.reseed(seed)
        
    @staticmethod
    def _xof(bytes32, a, b, length):
        """
        XOF: B^* x B x B -> B*
        """
        input_bytes = bytes32 + a + b
        if len(input_bytes) != 34:
            raise ValueError("Input bytes should be one 32 byte array and 2 single bytes.")
        return shake_128(input_bytes).digest(length)
        
    @staticmethod
    def _h(input_bytes):
        """
        H: B* -> B^32
        """
        return hashlib.sha3_256((input_bytes)).digest()
    
    @staticmethod  
    def _g(input_bytes):
        """
        G: B* -> B^32 x B^32
        """
        output = hashlib.sha3_512((input_bytes)).digest()
        return output[:32], output[32:]
    
    @staticmethod  
    def _prf(s, b, length):
        """
        PRF: B^32 x B -> B^*
        """
        input_bytes = s + b
        if len(input_bytes) != 33:
            raise ValueError("Input bytes should be one 32 byte array and one single byte.")
        c33=shake_256(input_bytes).digest(length)
        print("c33:",len(c33))
        return shake_256(input_bytes).digest(length)
    
    @staticmethod
    def _kdf(input_bytes, length):
        """
        KDF: B^* -> B^*
        """
        return shake_256(input_bytes).digest(length)
    
    def _generate_error_vector(self, sigma, eta, N, is_ntt=False):
        """
        Helper function which generates a element in the
        module from the Centered Binomial Distribution.
        """
        elements = []
        for i in range(self.k):
            input_bytes = self._prf(sigma,  bytes([N]), 64*eta)
            
            print("input bytes inside:", len(input_bytes))
            poly = self.R.cbd(input_bytes, eta, is_ntt=is_ntt)
            elements.append(poly)
            N = N + 1
        v = self.M(elements).transpose()
        print("input bytes:", len(input_bytes))
        return v, N
    
    def _generate_ts_vector(self, ts, eta, N, is_ntt=False):
        """
        Helper function which generates a element in the
        module from the Centered Binomial Distribution.
        """
        elementss = []
        for i in range(self.k):
            # input_bytes = self._prf(sigma,  bytes([N]), 64*eta)
            poly1 = self.R.cbd(ts, eta, is_ntt=is_ntt)
            elementss.append(poly1)
            N = N + 1
        v1 = self.M(elementss).transpose()
        return v1, N  
    def _generate_matrix_from_seed(self, rho, transpose=False, is_ntt=False):
        """
        Helper function which generates a element of size
        k x k from a seed `rho`.
        
        When `transpose` is set to True, the matrix A is
        built as the transpose.
        """
        A = []
        for i in range(self.k):
            row = []
            for j in range(self.k):
                if transpose:
                    input_bytes = self._xof(rho, bytes([i]), bytes([j]), 3*self.R.n)
                else:
                    input_bytes = self._xof(rho, bytes([j]), bytes([i]), 3*self.R.n)
                aij = self.R.parse(input_bytes, is_ntt=is_ntt)
                row.append(aij)
            A.append(row)
        return self.M(A)
        
    def _cpapke_keygen(self,PUF):
        """
        Algorithm 4 (Key Generation)
        https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf
        
        Input:
            None
        Output:
            Secret Key (12*k*n) / 8      bytes
            Public Key (12*k*n) / 8 + 32 bytes
        """
        # Generate random value, hash and split
        d = self.random_bytes(32)
        rho, sigma = self._g(d)
        # Set counter for PRF
        N = 0
        
        # Generate the matrix A ∈ R^kxk
        A = self._generate_matrix_from_seed(rho, is_ntt=True)
        # print("matrix A, ",A)
        # Generate the error vector s ∈ R^k
        s, N = self._generate_error_vector(sigma, self.eta_1, N)
        s.to_ntt()
        
        # Generate the error vector e ∈ R^k
        e, N = self._generate_error_vector(sigma, self.eta_1, N)
        e.to_ntt() 
                           
        # Construct the public key
        t = (A @ s).to_montgomery() + e
        
        # Reduce vectors mod^+ q
        t.reduce_coefficents()
        s.reduce_coefficents()
        # print("values rho: ",rho)  
        # Encode elements to bytes and return
        # print("values of t : ",t,"\nvalue of s: ",s)
        pk = t.encode(l=12) + rho
        sk = s.encode(l=12)
        # print("values public key: ",pk,"\nsecret key: ",sk)
        return pk, sk
        
    def _cpapke_enc(self, pk, m, coins):
        """
        Algorithm 5 (Encryption)
        https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf
        
        Input:
            pk: public key
            m:  message ∈ B^32
            coins:  random coins ∈ B^32
        Output:
            c:  ciphertext
        """
        N = 0
        rho = pk[-32:]
        
        tt = self.M.decode(pk, 1, self.k, l=12, is_ntt=True)        
        
        # Encode message as polynomial
        m_poly = self.R.decode(m, l=1).decompress(1)
        
        # Generate the matrix A^T ∈ R^(kxk)
        At = self._generate_matrix_from_seed(rho, transpose=True, is_ntt=True)
        
        # Generate the error vector r ∈ R^k
        print("coins:",coins)
        r, N = self._generate_error_vector(coins, self.eta_1, N)
        r.to_ntt()
        
        # Generate the error vector e1 ∈ R^k
        e1, N = self._generate_error_vector(coins, self.eta_2, N)
        print("value of e1=",e1)
        print("type of e1=",type(e1))
        # Generate the error polynomial e2 ∈ R
        input_bytes = self._prf(coins,  bytes([N]), 64*self.eta_2)
        e2 = self.R.cbd(input_bytes, self.eta_2)
        print("value of e2=",type(e2))
        
        
        # Get the current Unix timestamp
        timestamp = int(time.time())
        
        print("timestamp in enc:",timestamp)
        timestamp_bytes = timestamp.to_bytes(128, byteorder='big')
        print("timestamp bytes:", len(timestamp_bytes))
        t1, N = self._generate_ts_vector(timestamp_bytes, self.eta_2, N)
        print("value of t1=",t1)
# # Convert the timestamp to a 32-byte representation
#         d1 = struct.pack('>Q', timestamp)

        # #timestamp
        # timestamp=1234567890
        # # timestamp = np.zeros((1, 1), dtype=np.uint32)
        # timestamp1=self.M(timestamp)
        # # timestamp[0] = 1234567890  # Set the timestamp value
        # print("timestamp:",timestamp)
        
        
        
        # # Module/Polynomial arithmatic 
        
        # # d1 = self.random_bytes(32)
        # d1 = 1631743275
        # # d2=d1.to_ntt()
        # # # d2 = self.M.int_to_poly(d1)
        # d2, N = self._generate_error_vector(d1, self.eta_1, N)
        # # # print("d2 in enc:", d2)
        # d2.to_ntt()
        
        # u = (At @ r).from_ntt() + e1 + timestamp1
        
        #timestamp
        # e1_m, e1_n = e1.get_dim()
        # timestamp=1234567890
        # timestamp = np.zeros((1, 1), dtype=np.uint32)
        # #######timestamp1=self.element_to_mxn_list(timestamp,e1_m,e1_n)
        # timestamp[0] = 1234567890  # Set the timestamp value
        # print("timestamp:",timestamp)
        
        
        
        # Module/Polynomial arithmatic 
        
        # d1 = self.random_bytes(32)
        # d1 = 1631743275
        # d2=d1.to_ntt()
        # d2 = self.M.int_to_poly(d1)
        # d2, N = self._generate_error_vector(d1, self.eta_2, N)
        # print("d2 in enc:", d2)
        # d2.to_ntt()
        
        # timestamp = int(time.time()).to_bytes(length=8, byteorder='big')
        
        u = (At @ r).from_ntt() + e1 + t1
        # u_with_timestamp = u + timestamp
        
      

        
        print("value of U", u)
        #print("value of d2", d2)
        v = (tt @ r)[0][0].from_ntt()
        v = v + e2 + m_poly
        
        
        # Ciphertext to bytes
        c1 = u.compress(self.du).encode(l=self.du)
        c2 = v.compress(self.dv).encode(l=self.dv)
        # c3= d2.compress(self.dv).encode(l=self.dv)
        
        print ("c1: ",c1,"\nc2:",c2,"\nc1+c2:",c1+c2)
        
        return c1 + c2, timestamp
    
    def element_to_mxn_list(self,element, m, n):
        # mxn_list = []
        # for i in range(m):
        #     row = []
        #     for j in range(n):
        #         row.append(element)
        #     mxn_list.append(row)
        mxn_list = [[element]*n]*m
        return mxn_list

    
    def _cpapke_dec(self, sk, c,cc):
        """
        Algorithm 6 (Decryption)
        https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf
        
        Input:
            sk: public key
            c:  message ∈ B^32
        Output:
            m:  message ∈ B^32
        """
        # Split ciphertext to vectors
        print("decryption")
        index= self.du * self.k * self.R.n // 8
        # indexc2 = self.dv * self.k * self.R.n //8
        # c1 = c[:indexc1]
        # c2 = c[indexc1:(indexc1+indexc2)]
        c2 = c[index:]
        
        # Recover the vector u and convert to NTT form
        u = self.M.decode(c, self.k, 1, l=self.du).decompress(self.du)
        u.to_ntt()
        
        
        # Recover the polynomial v
        v = self.R.decode(c2, l=self.dv).decompress(self.dv)
        #d2 = self.R.decode(cc, l=self.dv).decompress(self.dv)
        N=0
        # d2 = self.M.int_to_poly(cc)
        
        # d2.to_ntt()
        # print("d2 in dec:",d2)
        # s_transpose (already in NTT form)
        st = self.M.decode(sk, 1, self.k, l=12, is_ntt=True)
        
        print("timestamp in dec:",cc)
        timestamp_bytess = cc.to_bytes(128, byteorder='big')
        print("timestamp bytes:", timestamp_bytess)
        t2, N = self._generate_ts_vector(timestamp_bytess, self.eta_2, N)
        print("value of t2=",t2)
        print("value of u=",u)
        print("value of v=",v)
        # k1 = u[0][0]- t2[0][0]   
        # m =( (st @ k1).from_ntt()) 
        # Recover message as polynomial
        #commenting  m =( (st @ u)[0][0].from_ntt())   
        # print("value of m=",m)
        # n=( (st @ t2).from_ntt())
        
        
        u = u-t2.to_ntt()
        m = v - ( (st @ u)[0][0].from_ntt())
        # Return message as bytes
        return m.compress(1).encode(l=1)
    
    def keygen(self):
        """
        Algorithm 7 (CCA KEM KeyGen)
        https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf
        
        Output:
            pk: Public key
            sk: Secret key
            
        """
        # Note, although the paper gens z then
        # pk, sk, the implementation does it this
        # way around, which matters for deterministic
        # randomness...
        pk, _sk = self._cpapke_keygen()
        z = self.random_bytes(32)
        
        # sk = sk' || pk || H(pk) || z
        sk = _sk + pk + self._h(pk) + z
        # print("values public key in keygen: ",pk,"\nsecret key in keygen: ",sk)
        return pk, sk
        
    def enc(self, pk, key_length=32):
        """
        Algorithm 8 (CCA KEM Encapsulation)
        https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf
        
        Input: 
            pk: Public Key
        Output:
            c:  Ciphertext
            K:  Shared key
        """
        m = self.random_bytes(32)
        print("message for encryption:", m)
        m_hash = self._h(m)
        Kbar, r = self._g(m_hash + self._h(pk))
        print("hash message for encryption:", m_hash)
        c,cc= self._cpapke_enc(pk, m_hash, r)
        K = self._kdf(Kbar + self._h(c), key_length)
        return c, K, cc

    def dec(self, c, sk, cc, key_length=32):
        """
        Algorithm 9 (CCA KEM Decapsulation)
        https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf
        
        Input: 
            c:  ciphertext
            sk: Secret Key
        Output:
            K:  Shared key
        """
        # Extract values from `sk`
        # sk = _sk || pk || H(pk) || z
        index = 12 * self.k * self.R.n // 8
        _sk =  sk[:index]
        pk = sk[index:-64]
        hpk = sk[-64:-32]
        z = sk[-32:]
        print("\ndecryption function")
        # Decrypt the ciphertext
        _m = self._cpapke_dec(_sk, c,cc)
        print("message after decryption:",_m)
        # # Decapsulation
        # _Kbar, _r = self._g(_m + hpk)
        # _c,_cc= self._cpapke_enc(pk, _m, _r)
        
        # # if decapsulation was successful return K
        # if c == _c:
        #     return self._kdf(_Kbar + self._h(c), key_length)
        # # Decapsulation failed... return random value
        # return self._kdf(z + self._h(c), key_length)

# Initialise with default parameters for easy import
Kyber512 = Kyber(DEFAULT_PARAMETERS["kyber_512"])
Kyber768 = Kyber(DEFAULT_PARAMETERS["kyber_768"])
Kyber1024 = Kyber(DEFAULT_PARAMETERS["kyber_1024"])
    
