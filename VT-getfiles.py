__author__ = 'itisnobody'
import requests
import sys
import os

# virustotal API key
apikey = "***"
# where to download files exists in virustotal
downloadfolder = "downloads-createdfiles"
# extension of files downloaded
extension = "danger"

# download file with the given hash and print the line number if it exists
def downloadfile(linenumber, hash):
    params = {'apikey': apikey,
              'hash': hash}
    # send request to download file with the given hash
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/download', params=params)
    downloaded_file = response.content

    # if file with the given hash exists
    if len(downloaded_file) > 0:
        # save the file found
        fw = open(downloadfolder + "/" + hash + "." + extension, "wb")
        fw.write(downloaded_file)
        fw.close()

# check the number of arguments entered
if len (sys.argv) != 4:
    print "Usage: python getfilesfromvt-v2.py <input-file> <starting-line-number> <number-of-lines>"
    sys.exit(1)

# create directories if they do not exist
if not os.path.exists("./" + downloadfolder):
    os.makedirs(downloadfolder)

# move program arguments to the arguments list
args = sys.argv[1:]

# starting line number to be read
startline = int(args[1])

# position in the file from where to start reading
filestartpos = (startline - 1) * 33

# number of lines to be read
maxlines = int(args[2])

# read the input file containing hashes and write last downloaded hash index
with open(args[0], 'rU') as fr, open("lastdownloadedindex.txt", 'w') as fw:
    count = 0
    # move cursor to the starting position in file
    fr.seek(filestartpos, 0)

    for line in fr:
        # check the hash and download the corresponding file if virustotal has it
        downloadfile(startline + count, line.rstrip())

        # print line number and the hash value in that line
        #print "%d. line: %s" %(int(args[1]) + count, line)

        count = count + 1
        if count == maxlines:
            fw.write(str(startline + count) + "<--- Line to be read next time!...")
            break

    # if file ended, print last line number read
    if count != maxlines:
        fw.write(str(startline + count) + "<--- Last line read. End of input file!...")
