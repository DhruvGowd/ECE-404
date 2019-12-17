#Z_n is a field if and only if n is a prime number

n = int(input('Enter a number less than or equal to 50: '))

isPrime = True
for j in range(2, n):
	if(n % j) == 0:
		isPrime = False

if isPrime:
	print('Field')
else:
	print('Ring')
