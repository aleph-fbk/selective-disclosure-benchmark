from pathlib import Path
import numpy
import matplotlib.pyplot as pplt
from matplotlib.collections import LineCollection
import seaborn
import math
import json
import sys
import os
import csv

from Algorithm import Algorithm
import sds_size

inchX = 9
inchY = 7.5
linewidth_model = 2

do_save = True
save_type = ['svg', 'pdf']
do_show = False
frame_off = False

do_plot_measured_size = True
do_plot_issuer_key = False

do_plot_hash_based = True
do_plot_sequential_disclosure = False
# for tree-based mechanisms, sequential disclosure is the ideal edge case and probably not representative
do_plot_tree_model = False

settingsPath = Path.cwd()/ 'matplotlib/pplt_settings'

mplstyle = settingsPath / 'mplstyle_two_column.mplstyle'
pplt.style.use( str(mplstyle))


data_path = Path.cwd()#/ 'data'
set_path = Path.cwd()/ 'matplotlib/sets/'
merkle_proofbytes_path = Path.cwd()/ 'benches'/ 'merkle_benchmark' / 'data'

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
            
hash_based = ['EdDSA', 'Dilithium', 'Falcon', 'Sphincs']
marker_sa_list = {'EdDSA':'4', 'Dilithium':'.', 'Falcon':'3', 'Sphincs':'v'}          
    
# number of attributes
na = 33

# number of disclosed attributes
nd = numpy.arange(1,na+1)

### all sizes in bytes, except where otherwise noted //8

salt_size = 16

digest_size = 32

sa_skip_model = []# + hash_based

sa_skip_measurement = ['CL', 'BBS', 'BBS+', 'PS', 'Commitment list']

signature_algorithm_string_proof_size_data = [] #['cl', 'bbs', 'merkle']
for sa in signature_algorithm:
    signature_algorithm_string_proof_size_data.append(sa.name.lower().replace('+', ''))
    

    
fig1 = pplt.figure()
fig1.set_size_inches(inchX, inchY, forward=True)
ax1 = fig1.gca()

ax1.set_xlabel(r'holder proof [bytes]')
ax1.set_ylabel(r'public key [bytes]')

ax1.set_title(f"Holder proof vs. public key size")
ax1.set_xscale('symlog', base=2)
ax1.set_yscale('symlog', base=2)

def scatter(ax, x, y, colors, label, marker):

    points = numpy.array([x, y]).T.reshape(-1, 1, 2)
    segments = numpy.concatenate([points[:-1], points[1:]], axis=1)
    lc = LineCollection(segments, colors=cp_sa)#, label=_set['name'])
    lc.set_linewidth(2)
    line = ax1.add_collection(lc)
    ax.scatter(x, y, c=colors, s=128, label=label, marker=marker)

for sa in signature_algorithm:

    si = signature_algorithm.index(sa)

    cp_sa = seaborn.color_palette(f"blend:{sa.color2},{sa.color}", n_colors = na)
    

    # if public key size is fixed for the algorithm:
    if sa.public_key_bytes:
        public_key_bytes = sa.public_key_bytes
        
    else: # for selective disclosure signatures, public key size is a function of the number of credential attributes
        public_key_bytes = sds_size.public_key(sa.name, na)    
        
    if sa.name not in sa_skip_model:
    
        # for SD signatures, compute disclosure size as function of na and nd
        if sa.name not in hash_based:
            
            data_sa = sds_size.disclosure(sa.name, na, nd)

            scatter(ax=ax1, x=data_sa, y=numpy.full(na,public_key_bytes), colors=cp_sa, label=sa.set_name, marker=sa.marker)
            
        # for hash-based mechanisms, plot the hash list disclosure size
        else:

            data_sa = digest_size*na + sa.signature_bytes + salt_size*nd
            
            scatter(ax=ax1, x=data_sa, y=numpy.full(na,public_key_bytes), colors=cp_sa, label=sa.set_name+r' $\texttt{cmtList}$', marker=marker_sa_list[sa.name])
            
        if do_plot_tree_model:

            data_sa_tree = digest_size + sa.signature_bytes + salt_size * nd + digest_size * nd * numpy.ceil(numpy.log2(na))
            
            scatter(ax=ax1, x=data_sa, y=numpy.full(na,public_key_bytes), colors=cp_sa, label=sa.set_name, marker=sa.marker)
            
    # load and plot measured proof size
    
    if sa.name not in sa_skip_measurement and do_plot_measured_size is True:
        
        measured_proof_size = numpy.empty(na, dtype = numpy.int_)
        
        # Merkle inclusion path size doesn´t include signature over root, or one salt per disclosed attribute
        #elif sa == 'Merkle':
        if sa.name in hash_based:
            
            if do_plot_sequential_disclosure:

                with open(merkle_proofbytes_path/f'merkle_proofbytes.csv') as f:
            
                    reader = csv.DictReader(f, skipinitialspace=True)
                    
                    for row in reader:
                        measured_proof_size[int(row['nD'])-1] = row['bytes']

                measured_proof_size += sa.signature_bytes + salt_size*nd
                
                scatter(ax=ax1, x=measured_proof_size, y=numpy.full(na,sa.public_key_bytes), colors=cp_sa, label=sa.set_name+' sequential disclosure', marker=sa.marker)
                
            # load the random sampling
            
            sampled_proof_size_median = numpy.empty(na, dtype = numpy.int_)
            sampled_proof_size_25 = numpy.empty(na, dtype = numpy.int_)
            sampled_proof_size_75 = numpy.empty(na, dtype = numpy.int_)
            
            with open(merkle_proofbytes_path/'merkle_rand_proofbytes.csv') as f2:
            
                reader2 = csv.DictReader(f2, skipinitialspace=True)
                
                for row in reader2:
                    sampled_proof_size_median[int(row['x'])-1] = row['median'].split('.')[0]
                    sampled_proof_size_25[int(row['x'])-1] = row['percentile25'].split('.')[0]
                    sampled_proof_size_75[int(row['x'])-1] = row['percentile75'].split('.')[0]
        
                sampled_proof_size_median += sa.signature_bytes + salt_size*nd
                sampled_proof_size_25 += sa.signature_bytes + salt_size*nd
                sampled_proof_size_75 += sa.signature_bytes + salt_size*nd
        
                scatter(ax=ax1, x=sampled_proof_size_median, y=numpy.full(na,public_key_bytes), colors=cp_sa, label=sa.set_name+r' $\texttt{merTree}$', marker=sa.marker)
                #ax1.fill_between(nd, sampled_proof_size_25, sampled_proof_size_75, alpha=0.2, color=color)
            
        else:
    
            with open(data_path/f'{signature_algorithm_string_proof_size_data[si]}_proofbytes_data.csv') as f:
            
                reader = csv.DictReader(f, skipinitialspace=True)
                
                for row in reader:
                    measured_proof_size[int(row['nD'])-1] = row['bytes']
                    
            scatter(ax=ax1, x=measured_proof_size, y=numpy.full(na,public_key_bytes), colors=cp_sa, label=sa.set_name+' measured', marker=sa.marker)

ax1.legend(loc='right', frameon=True, bbox_to_anchor=(.93, .503))

ax1.patch.set_facecolor('w')
ax1.grid(True, color='black', alpha=.1, which='both', linestyle='-')
#ax1.autoscale_view()

ax1.legend(framealpha=0.5)
#put labels outside
#ax1.legend(loc='right', bbox_to_anchor=(1.56, .46))

if frame_off:
    for pos in ['right', 'top', 'bottom', 'left']:
        fig1.gca().spines[pos].set_visible(False)
    
if do_save:
    
    if not os.path.isdir('plots'):
        os.makedirs('plots')

    for st in save_type:
        
        save_name = 'key_vs_holder_proof'
        
        pplt.savefig( f'plots/{save_name}.{st}')

if do_show:
    
    pplt.show()
        
    

