from kyber import Kyber
# from test_kyber import 


(k,v) = Kyber({
        "n" : 256,
        "k" : 3,
        "q" : 3329,
        "eta_1" : 2,
        "eta_2" : 2,
        "du" : 10,
        "dv" : 4,
    }).keygen()

# print("values k: ",type(k),"\nv: ",v)
# byte_val = b'\x00\x01'
 
# converting to int
# byteorder is big where MSB is at start
# int_val = int.from_bytes(k)
 
# printing int equivalent
# print(int_val)