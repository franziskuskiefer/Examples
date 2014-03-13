#!/usr/bin/python3

import argparse, random
import groups

######################
# Pedersen VSS
######################

# load group
g2048 = groups.MODP2048()


def genRand(m):
	return random.SystemRandom().randint(0,m)
	
def pedersen(m, r):
	return (pow(g2048.g,m,g2048.p)*pow(g2048.h,r,g2048.p))%g2048.p

def commit(m):
	r = genRand(p)
	c = pedersen(m, r)
	return [c, r]

# f0 + f1*x + f2*x^2 + ....
def poly(x, f):
	result = 0
	for i in range(len(f)):
		result += f[i]*pow(x,i,g2048.p)
	return result

# Compute shares for Pedersen VSS
def pedersenSharing(k, t, n):
	# define polynomials
	f = [k]	
	v = [genRand(g2048.p)]
	for i in range(1, t):
		f.append(genRand(g2048.p))
		v.append(genRand(g2048.p))

	# compute shares
	s1 = [k]
	s2 = [v[0]]
	for i in range(1, n+1):
		s1.append(poly(i, f))
		s2.append(poly(i, v))
	
	# compute commitments
	C = []
	for i in range(0, t):
		C.append(pedersen(f[i], v[i]))
	
	return (s1, s2, C)
	
# Verify a Pedersen share
def pedersenVerify(i, s1, s2, C):
	v = pedersen(s1, s2)
	w = 1
	for j in range(len(C)):
		w = (w*pow(C[j],i**j,g2048.p))%g2048.p
	return v == w

def sssRecover(ts, s):
	k = 0
	for i in range(len(ts)):
		l = 1
		for j in range(len(ts)):
			if j != i:
				l *= (ts[j]*pow(ts[j]-ts[i], g2048.p-2, g2048.p))%g2048.p
		k += (s[ts[i]-1]*l)
	return k%g2048.p

def pedersenRecover(ts, s1, s2, C):
	for i in range(len(ts)):
		if not pedersenVerify(ts[i], s1[ts[i]-1], s2[ts[i]-1], C):
			return 'wrong share!'
	return sssRecover(ts, s1)

def encode(c):
	x = ord(c)
	if x > 32 and x < 127:
		return x-33
	print("Sorry, I can only handle standard ASCII characters 33-126!")
	exit(1)

def strToInt(s):
	n = len(s)
	f = 0
	for i in range(n):
		f += encode(s[i])*(94**(n-i-1)) # create integer from base 94 string (characters)
	return f

# Pedersen VSS main
def main(args):
	k = strToInt(args.secret)

	# compute shares
	s1, s2, C = pedersenSharing(k, 3, 5)
	
	# check shares
	check = pedersenVerify(1, s1[1], s2[1], C)
	check = check and pedersenVerify(2, s1[2], s2[2], C)
	if check:
		print("got correct shares :)")
	else:
		print("the dealer is cheating :(")
		
	# (secure) shares without key!
	s1s = s1[1:]
	s2s = s2[1:]
	
	# recovery
	recoveredK = pedersenRecover([5, 2, 3], s1s, s2s, C)
	if recoveredK == k:
		print("correct key recovery :)")
	else:
		print("something went wrong during recovery :(")
	
if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Create secret shares')
	parser.add_argument('secret', metavar='\"secret\"', type=str, help='the secret to share')
	args = parser.parse_args()
	main(args)
