# benchmark primality test for a number of independent runs

import os

prime_test = 'cargo bench --bench=prime'
copy_results = 'cp -r target/criterion/safe\ prime/new target/criterion/safe\ prime/new_'


for i in range(7):

	os.system(prime_test)
	os.system(copy_results+str(i))

