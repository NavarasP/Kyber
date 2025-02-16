from kyber import Kyber512
import time
start=time.perf_counter()
pk, sk = Kyber512.keygen()
end=time.perf_counter()
print("time of keygen:",end-start)

start=time.perf_counter()
c, key,cc = Kyber512.enc(pk)
end=time.perf_counter()
print("time of enc:",end-start)

start=time.perf_counter()
_key = Kyber512.dec(c, sk,cc )
end=time.perf_counter()
print("time of dec:",end-start)

# assert key == _key 
