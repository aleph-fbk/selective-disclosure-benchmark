from pathlib import Path
import numpy
import matplotlib.pyplot as pplt
import seaborn
import math
import os
import csv
from tomlkit import load
import sds_size

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

do_use_dock_libraries = True

settingsPath = Path.cwd()/ 'matplotlib/pplt_settings'

mplstyle = settingsPath / 'mplstyle_two_column.mplstyle'
pplt.style.use( str(mplstyle))

data_path = Path.cwd()/ 'data'
set_path = Path.cwd()/ 'matplotlib/sets/'

dock_libraries = ['BBS+', 'BBS']

signature_algorithm = ['CL',
            'BBS+',
            'BBS',
            #'BBS BLS12-381-SHA-256',
            'PS'
            ]
            
hash_based = ['Merkle', 'Dilithium', 'Falcon']#, 'Sphincs']

if do_plot_hash_based:
    
    signature_algorithm += hash_based

# number of attributes
na = 33

# number of disclosed attributes
nd = numpy.arange(1,na+1)

### all sizes in bytes, except where otherwise noted //8

salt_size = 16

digest_size = 32

# attribute size is arbitrary, so not included

# size of hash list disclosure = 
# one salt, one hash per attribute
# + signature of the list
# + one disclosed salt per disclosed attribute

#hash_list = digest_size*na + signature_size_eddsa_ed25519 + salt_size*nd
#hash_list_pk_Iss = pk_size_eddsa_ed25519

# size of hash tree disclosure = 
# one tree root (digest size)
# + one signature of the tree root
# + one disclosed salt per disclosed attribute
# + one inclusion proof per disclosed attribute, estimated equal to the tree height = ceil(log2(number of attributes))* digest_size for each node.
### (ceil(log2(number of attributes+1))-1) * digest_size for each node.
# https://www.geeksforgeeks.org/relationship-number-nodes-height-binary-tree/

#hash_tree =         digest_size + signature_size_eddsa_ed25519 + salt_size * nd + digest_size * nd * numpy.ceil(numpy.log2(na))
#hash_tree_pk_Iss = pk_size_eddsa_ed25519




#signature_algorithm = ['CL', 'BBS+', 'Merkle', 'Commitment list']#, 'PS']

#signature_algorithm_string = ['CL', 'BBS+', 'Merkle + ed25519', 'cmtList +  ed25519', 'PS']

sa_skip_model = ['PS']# + hash_based

sa_skip_measurement = ['CL', 'BBS', 'BBS+', 'PS', 'Commitment list']

signature_algorithm_string_proof_size_data = [] #['cl', 'bbs', 'merkle']
for sa in signature_algorithm:
    signature_algorithm_string_proof_size_data.append(sa.lower().replace('+', ''))



key_info = [r' without $\texttt{pk_{Iss}}$', r' with $\texttt{pk_{Iss}}$']

#data_sa = [cl, bbs_plus, hash_tree, hash_list]
#data_sa_pk_Iss = [cl_pk_Iss, bbs_plus_pk_Iss, hash_tree_pk_Iss, hash_list_pk_Iss]



#colorblind = seaborn.color_palette('colorblind', n_colors=len(signature_algorithm))

#colorblind_key = []
#for sa in range(len(signature_algorithm)):

#    cp_a = seaborn.light_palette(colorblind[(sa-1)%len(signature_algorithm)], reverse=True, n_colors=4)
#    colorblind_key.append(cp_a)

#marker_sa = ['x', '+', '2', '$l$', '.']

fig1 = pplt.figure()
ax1 = fig1.gca()

ax1.set_xlabel(r'Disclosed Attributes $n_d$')
ax1.set_ylabel(r'Holder Presentation Proof [bytes]')


for sa in signature_algorithm:
    si = signature_algorithm.index(sa)
    
    with open(f'{set_path}/{sa.lower()}.toml') as f:
        S = load(f)
        
        color = f"#{S['family']['color']}"
        color2 = f"#{S['family']['color2']}"
            
        marker_sa = f"{S['family']['marker']}"
    
        _set = [s for s in S['set'].values() if s['security_level']<=2][0]
        
        s_name = _set['name']
        
        if sa in hash_based:
            public_key_bytes = _set['public_key_bytes']
            signature_bytes = _set['signature_bytes']
        
    if sa not in sa_skip_model:
    
        # for SD signatures, compute disclosure size as function of na and nd
        if sa not in hash_based:

            data_sa = sds_size.disclosure(sa, na, nd)

            ax1.plot(nd, data_sa, linewidth=linewidth_model, linestyle='-', marker=marker_sa, color=color, label=_set['name']+' model')
            
        # for hash-based mechanisms, plot the hash list disclosure size
        else:

            data_sa = digest_size*na + signature_bytes + salt_size*nd

            ax1.plot(nd, data_sa, linewidth=linewidth_model, linestyle=':', marker=marker_sa, color=color, label=_set['name']+r' $\texttt{cmtList}$')

        if do_plot_tree_model:

            data_sa_tree = digest_size + signature_bytes + salt_size * nd + digest_size * nd * numpy.ceil(numpy.log2(na))

            ax1.plot(nd, data_sa_tree, linewidth=linewidth_model, linestyle='-', marker=marker_sa, color=color2, label=_set['name']+' model')
        
        #if do_plot_issuer_key:
        
        #    ax1.plot(nd, data_sa[si]+data_sa_pk_Iss[si], linewidth=linewidth_model, linestyle='-', color=colorblind_key[si][2], label=signature_algorithm_string[si]+key_info[1])

    # load and plot measured proof size
    
    if sa not in sa_skip_measurement and do_plot_measured_size is True:
        
        measured_proof_size = numpy.empty(na, dtype = numpy.int_)
        
        # Merkle inclusion path size doesn´t include signature over root, or one salt per disclosed attribute
        #elif sa == 'Merkle':
        if sa in hash_based:
            
            if do_plot_sequential_disclosure:

                with open(data_path/f'merkle_proofbytes_data.csv') as f:
            
                    reader = csv.DictReader(f, skipinitialspace=True)
                    
                    for row in reader:
                        measured_proof_size[int(row['nD'])-1] = row['bytes']

                measured_proof_size += signature_bytes + salt_size*nd
            
                ax1.plot(nd, measured_proof_size, linewidth=linewidth_model//2, linestyle='dotted', marker=marker_sa, color=color2, label=_set['name']+' sequential disclosure')
            
            # load the random sampling
            
            sampled_proof_size_median = numpy.empty(na, dtype = numpy.int_)
            sampled_proof_size_25 = numpy.empty(na, dtype = numpy.int_)
            sampled_proof_size_75 = numpy.empty(na, dtype = numpy.int_)
            
            with open(data_path/f'merkle_rand_proofbytes_data.csv') as f2:
            
                reader2 = csv.DictReader(f2, skipinitialspace=True)
                
                for row in reader2:
                    sampled_proof_size_median[int(row['x'])-1] = row['median'].split('.')[0]
                    sampled_proof_size_25[int(row['x'])-1] = row['percentile25'].split('.')[0]
                    sampled_proof_size_75[int(row['x'])-1] = row['percentile75'].split('.')[0]
        
                sampled_proof_size_median += signature_bytes + salt_size*nd
                sampled_proof_size_25 += signature_bytes + salt_size*nd
                sampled_proof_size_75 += signature_bytes + salt_size*nd
        
                ax1.plot(nd, sampled_proof_size_median, linewidth=linewidth_model//2, linestyle='solid', marker=marker_sa, color=color, label=_set['name']+r' $\texttt{merTree}$')
                ax1.fill_between(nd, sampled_proof_size_25, sampled_proof_size_75, alpha=0.2, color=color)
            
        else:
    
            with open(data_path/f'{signature_algorithm_string_proof_size_data[si]}_proofbytes_data.csv') as f:
            
                reader = csv.DictReader(f, skipinitialspace=True)
                
                for row in reader:
                    measured_proof_size[int(row['nD'])-1] = row['bytes']
                    
            ax1.plot(nd, measured_proof_size, linewidth=linewidth_model//2, linestyle='dotted', marker=marker_sa, color=color, label=_set['name']+' measured')
        
if do_plot_issuer_key and not do_plot_measured_size:
    ax1.set_ylim([-20, 2000])

#ax1.legend(loc=0, frameon=True)
ax1.legend(loc='center left', bbox_to_anchor=(1, .5))
#ax1.legend(bbox_to_anchor=(.2, .8))
ax1.patch.set_facecolor('w')
ax1.grid(True, color='black', alpha=.1, which='both', linestyle='-')

if frame_off:
    for pos in ['right', 'top', 'bottom', 'left']:
        fig1.gca().spines[pos].set_visible(False)
    
if do_save:

    if not os.path.isdir('plots'):

        os.makedirs('plots')

    for st in save_type:
    
        pplt.savefig( f'plots/presentation_proof_size_na_{na}.{st}')
    
    
if do_show:
    
    pplt.show()
    
    


