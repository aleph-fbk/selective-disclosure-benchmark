from pathlib import Path
import numpy
import matplotlib.pyplot as pplt
from matplotlib.collections import LineCollection
import seaborn
import math
import json
import sys
import os

from Algorithm import Algorithm
import sds_size


inchX = 9.5 #inchX = 9
inchY = 5 #inchY = 6
linewidth_model = 2

do_save = True
save_type = ['svg', 'pdf']
do_show = False
frame_off = False

do_plot_hash_based = True
do_use_dock_libraries = True

add_safe_prime = False

settingsPath = Path.cwd()/ 'matplotlib/pplt_settings'

mplstyle = settingsPath / 'mplstyle_two_column.mplstyle'
pplt.style.use( str(mplstyle))


#data_path = Path.cwd()/ 'data/bbs_benchmark_202309_data_5800X'
data_path = Path.cwd()#/ 'target/criterion/'
set_path = Path.cwd()/ 'matplotlib/sets/'

signature_algorithm = [Algorithm('CL', 'ursa', set_path, data_path),
            Algorithm('BBS+', 'dock', set_path, data_path),
            Algorithm('BBS', 'dock', set_path, data_path),
            Algorithm('PS', 'ursa', set_path, data_path)
            ]

if do_plot_hash_based:
    
    signature_algorithm += [Algorithm('EdDSA', 'merkle', set_path, data_path),
            Algorithm('Dilithium', 'merkle', set_path, data_path),
            Algorithm('Falcon', 'merkle', set_path, data_path),
            Algorithm('Sphincs', 'merkle', set_path, data_path)
            ]
    
algorithm_function = ['keygen']

algorithm_function_string = ['$\mathtt{keyGen}$']

# number of attributes, total signed
nA = [4, 8, 16, 33]
A = len(nA)

    
fig1 = pplt.figure()
fig1.set_size_inches(inchX, inchY, forward=True)
ax1 = fig1.gca()

ax1.set_xlabel(f'public key size [bytes]')
ax1.set_ylabel(f'{algorithm_function_string[0]} [ms]')

ax1.set_title(f"Key generation")



for sa in signature_algorithm:

    si = signature_algorithm.index(sa)
            
    key_size = numpy.zeros((len(nA)))
    
    median = numpy.zeros((len(nA)))
    quartile1 = numpy.zeros((len(nA)))
    quartile3 = numpy.zeros((len(nA)))
    
    if sa.name == 'CL' and add_safe_prime is True:
    
        median_safeprime = numpy.zeros((len(nA)))
        quartile1_safeprime = numpy.zeros((len(nA)))
        quartile3_safeprime = numpy.zeros((len(nA)))
        
    for na in range(len(nA)):
        
        cp_sa = seaborn.color_palette(f"blend:{sa.color2},{sa.color}", n_colors = len(nA))
        #cp_sa = seaborn.color_palette(f"blend:{color2},{color}", as_cmap=True)
        
        # if public key size is fixed for the algorithm:
        if sa.public_key_bytes:
            key_size[na] = sa.public_key_bytes
            
        else: # for selective disclosure signatures, public key size is a function of the number of credential attributes
            key_size[na] = sds_size.public_key(sa.name, na)
        
        for af in range(len(algorithm_function)):
            
            dataPathPoint = sa.data_path / f'{sa.folder_name} {algorithm_function[af]}/{nA[na]}'
        
            try:
                with open(dataPathPoint/'new/sample.json') as f:
                
                    point = json.load(f)
                    times = numpy.asarray(point['times'])
                    iterations = numpy.asarray(point['iters'], dtype = numpy.int_)

                    quartile1[na], median[na], quartile3[na] = numpy.percentile((times/iterations)/1e6, [25, 50, 75])
                    
                if sa == 'CL' and add_safe_prime is True:

                    dataPathSafe_p = data_path / f'safe prime/new_{2*na}'
                    dataPathSafe_q = data_path / f'safe prime/new_{2*na+1}'
                
                    with open(dataPathSafe_p /'sample.json') as f_p:
                    
                        with open(dataPathSafe_q /'sample.json') as f_q:
                            data_p = json.load(f_p)
                            data_q = json.load(f_q)
                            
                            times_pq = numpy.asarray((data_p['times'], data_q['times']))
                            iterations_pq = numpy.asarray((data_p['iters'], data_q['iters']), dtype = numpy.int_)

                            quartile1_safeprime[na], median_safeprime[na], quartile3_safeprime[na] = numpy.percentile((times_pq/iterations_pq)/1e6, [25, 50, 75])
                            
                            quartile1[na] += quartile1_safeprime[na]
                            median[na] += median_safeprime[na]
                            quartile3[na] += quartile3_safeprime[na]
                            
            except OSError as e:
            
                print(e)
    
    
    x = key_size
    y = median
    
    points = numpy.array([x, y]).T.reshape(-1, 1, 2)
    segments = numpy.concatenate([points[:-1], points[1:]], axis=1)

    lc = LineCollection(segments, colors=cp_sa)
    lc.set_linewidth(2)
    #lc.set_array(cols)
    #lc.set_linestyle('-')
    line = ax1.add_collection(lc)
    
    ax1.scatter(x, y, c=cp_sa, s=128, label=sa.set_name, marker=sa.marker)

ax1.set_xscale('symlog', base=2)
ax1.set_yscale('log')

ax1.patch.set_facecolor('w')
ax1.grid(True, color='black', alpha=.1, which='both', linestyle='-')
ax1.autoscale_view()

#put labels outside
#box = ax1.get_position()
#ax1.legend(loc='center left', bbox_to_anchor=(.7, .4))
ax1.legend()

#ax1.set_aspect('equal', adjustable='box')

if frame_off:
    for pos in ['right', 'top', 'bottom', 'left']:
        fig1.gca().spines[pos].set_visible(False)
    
if do_save:

    if not os.path.isdir('plots'):
    
        os.makedirs('plots')

    save_name = 'keygen_scatter'
    
    if do_plot_hash_based:
        
        save_name += '_with_hash_based'
        
    for st in save_type:
            
        pplt.savefig( f'plots/{save_name}.{st}')
    
    
if do_show:
    pplt.show()
        
    


