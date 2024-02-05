from pathlib import Path
import numpy
import matplotlib.pyplot as pplt
import seaborn
import math
import json
import sys

inchX = 9
inchY = 6
linewidth_model = 2

do_save = True
save_type = ['svg', 'pdf']
do_show = False
frame_off = False

settingsPath = Path.cwd()/ 'matplotlib/pplt_settings'

colors = []

with open(settingsPath / 'colours_Japan.txt') as f:
	for line in f:
		if line.strip():	# if line not empty
			colors.append( '#' + line.split('\t')[0] )

x = settingsPath / 'mplstyle_two_column.mplstyle'
pplt.style.use( str(x))



dataPath = Path.cwd()/ 'data/bbs_benchmark_202309_data_5800X'

signature_algorithm = ['BBS', 'CL', 'BBS+']

algorithm_function = ['presentation generation', 'presentation verification']


# number of attributes, total signed
nA = [2, 4, 8, 16, 33]


K = len(nA)
ygbd = seaborn.color_palette('YlGnBu_d', n_colors=K)
yord = seaborn.color_palette('YlOrRd_d', n_colors=K)


for sa in signature_algorithm:
	for af in algorithm_function:

		fig1 = pplt.figure()
		fig1.set_size_inches(inchX, inchY, forward=True)
		ax1 = fig1.gca()

		ax1.set_xlabel(r'disclosed attributes $n_d$')
		ax1.set_ylabel(r'time $[ms]$')


		for na in range(len(nA)):

			# number of attributes, disclosed
			
			nD = range(1, nA[na] + 1)
			
			#if nA[na] == 4:
			#	nD = [1, 2, 4]
			#else:
			#	nD = [1, nA[na]//4, nA[na]//2, nA[na]]
				
			median = numpy.zeros(len(nD))
			quartile1 = numpy.zeros(len(nD))
			quartile3 = numpy.zeros(len(nD))
			
			for nd in range(len(nD)):
				
				if sa == 'BBS' or sa == 'BBS+':
				    lib = 'dock '
				else:
				    lib = ''
				dataPathProofGen = dataPath / f'{lib}{sa} {af} with {nA[na]} attributes/Revealing {nD[nd]} attributes'
				
				with open(dataPathProofGen/'new/sample.json') as f:
				
					proofGen = json.load(f)
					times = numpy.asarray(proofGen['times'])
					iterations = numpy.asarray(proofGen['iters'], dtype = numpy.int8)

					quartile1[nd], median[nd], quartile3[nd] = numpy.percentile((times/iterations)/1e6, [25, 50, 75])



			ax1.plot(nD, median, linewidth=linewidth_model, linestyle='-', color=yord[na], label=f'$n_A={nA[na]}$')
			ax1.fill_between(nD, quartile1, quartile3, alpha=0.2, color=yord[na])
					
		#ax1.plot(nd, hash_tree, linewidth=linewidth_model, linestyle='-', color=colors[1], label='hash tree')
		#ax1.plot(nd, bbs_plus, linewidth=linewidth_model, linestyle='-', color=colors[2], label='BBS+')
		#ax1.plot(nd, hash_tree_multiproof, linewidth=linewidth_model, linestyle='-.', color=colors[3], label='hash tree multiproof')

		    
		lg1 = ax1.legend(loc=0, frameon=True)

		ax1.patch.set_facecolor('w')
		ax1.grid(True, color='black', alpha=.1, which='both', linestyle='-')

		if frame_off:
			for pos in ['right', 'top', 'bottom', 'left']:
				fig1.gca().spines[pos].set_visible(False)
		    
		if do_save:
			for st in save_type:
				pplt.savefig( f'{sa}_{af}.{st}')
			
			
		if do_show:
			
			pplt.show()
			
	


