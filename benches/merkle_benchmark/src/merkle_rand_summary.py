from pathlib import Path
import csv
import numpy
import os

#read .csv files and compute quartiles
median_range, mean_range, min_range, max_range = [], [], [], []
percentile25_range, percentile75_range = [], []

fieldnames = ['x','percentile25','median','percentile75']

data_path = Path.cwd()/ 'data'

if not os.path.isdir(data_path):

    os.makedirs(data_path)
    
with open(data_path/f'merkle_rand_proofbytes.csv', 'a+') as f_out:

    writer = csv.DictWriter(f_out, fieldnames=fieldnames)
    writer.writeheader()
        
    for nd in range(1, 34):
        
        data = []
        
        with open(data_path/'merkle_rand'/f'{nd}.csv', 'r') as f:
                
            reader = csv.reader(f, skipinitialspace=True)

            for row in reader:
                
                data.append(int(row[0]))
                
        quartile = numpy.percentile(data, [25, 50, 75])
        
        writer.writerow({'x': int(nd), 'percentile25': quartile[0], 'median': quartile[1], 'percentile75': quartile[2]})

