from random import randrange
from secrets import randbits
from time import time

# Generate a random 1024-bit odd integer
# We use 'secrets' instead of 'random' for cryptographic security


#to understand the why of this 
##go back in history
#https://www.youtube.com/watch?v=tBzaMfV94uA&vl=fr

#you need to try to find from small to big number by hand
#there are hand algos to test if a prime easily but effiecnet for big prime numbers
# translate to it into an algorithm for you pc





# credit https://gist.github.com/Ayrx/5884790

def miller_rabin(n, k=40):
    """
    Miller-Rabin Primality Test
    :param n: Number to test
    :param k: Number of rounds (40 is standard for RSA)
    :return: True if probably prime, False if composite
    """
    # Small prime cases
    if n <= 1: return False
    if n <= 3: return True
    if n % 2 == 0: return False

    # Find r and s such that n - 1 = 2^r * s
    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2

    for _ in range(k):
        a = randrange(2, n - 1)
        x = pow(a, s, n)
        
        if x == 1 or x == n - 1:
            continue
            
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            # If the loop didn't break, it's composite
            return False
            
    return True
    
stop=False


start_timer = time()
while stop is False:
    candidate = randbits(1024) | 1
    if miller_rabin(candidate, 40):
        stop=True
        print(f"Found a 1024-bit prime: {candidate}")
        print("VERIFY ==> https://www.calculatorsoup.com/calculators/math/prime-number-calculator.php")
        print(f"it took {(time()-start_timer)/60} mins")
    else:
        print("This number is composite. Try again!")
