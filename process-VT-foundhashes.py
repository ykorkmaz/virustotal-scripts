__author__ = 'itisnobody'

import os

infile = "VT-foundhashes-diger.csv"
overfile = "diger-found-created-hashes-over30.txt"
belowfile = "diger-found-created-hashes-below30.txt"

if os.path.exists(os.path.join('.', infile)):
    with open(infile, 'r') as fi, open(overfile, 'w') as fo, open(belowfile, 'w') as fb:
        fi.readline()
        for line in fi:

            filehash = line.rstrip().split(",")[0][1:-1]
            poscount = int(line.rstrip().split(",")[2][1:-1])

            if poscount > 30:
                fo.write(filehash + "\n")
            else:
                fb.write(filehash + "\n")