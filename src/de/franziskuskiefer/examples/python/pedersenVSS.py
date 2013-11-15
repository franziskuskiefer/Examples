#!/usr/bin/python3

import sys, argparse, random, string

# modp2048 group and h
p = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
g = 2
h = int("3d941d6d9cd4c77719840d6b391a63ca6ded5b5cf6aafeefb9ea530f523039e9c372736a79b7eb022e50029f7f2cb4fb16fd1def75657288eca90d2c880f306be76fe0341b3c8961ae6e61aabbb60e416069d97eeada2f1408f2017449dddcd5ac927f164b1a379727941bd7f2170d02ef12ef3ec801fae585ac7b9d4079f50feced64687128208d46e3e10c5d78eb05832f5322c07a3b4e14c6f595206fde99115e8eea19b5fb13dd434332ec3eccb41a4baa54a14183c3416313678697db8507abdcfc6a97c86099fa5172316d784c6997fc2e74e8e59c7c1bc90426164682f5bfbf6373b13ea90d7e13fbffd65e10c4ad96c38ccbf8e8def28d76746729dc", 16)

######################
# Pedersen VSS
######################

def genRand(m):
	return random.SystemRandom().randint(0,m)
	
def pedersen(m, r):
	return (pow(g,m,p)*pow(h,r,p))%p

def commit(m):
	r = genRand(p)
	c = pedersen(m, r)
	return [c, r]

# f0 + f1*x + f2*x^2 + ....
def poly(x, f):
	result = 0
	for i in range(len(f)):
		result += f[i]*pow(x,i,p)
	return result

# Compute shares for Pedersen VSS
def pedersenSharing(k, t, n):
	# define polynomials
	f = [k]	
	v = [genRand(p)]
	for i in range(1, t):
		f.append(genRand(p))
		v.append(genRand(p))

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
		w = (w*pow(C[j],i**j,p))%p
	return v == w

def sssRecover(ts, s):
	k = 0
	for i in range(len(ts)):
		l = 1
		for j in range(len(ts)):
			if j != i:
				l *= (ts[j]*pow(ts[j]-ts[i], p-2, p))%p
		k += (s[ts[i]-1]*l)
	return k%p

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
