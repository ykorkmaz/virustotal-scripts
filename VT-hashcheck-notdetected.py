__author__ = 'itisnobody'

import simplejson
import urllib
import urllib2
import sys
import os
import Queue
import threading
import fnmatch

# virustotal API key
apikey = "****provide-key****"
# virustotal report URL
reporturl = "https://www.virustotal.com/vtapi/v2/file/report"
# output file to write the VT check results
outfile = "tt-found-notdetected-hashes.txt"
# last checked line number in hashes file
lastcheckedindexfile = "lastcheckedindex.txt"
# file containing hashes
hashesfile = "tt-created-hashes.txt"
# number of threads to be spawned
threadnum = 4

#islimitreached = False
# queue holding all the hashes to be checked
hashqueue = Queue.Queue()

# thread class for retrieving Virus Total check results
class ThreadVTCheck(threading.Thread):
    def __init__(self, hsqueue, lockfile, lastlock):
        threading.Thread.__init__(self)
        self.myhashqueue = hsqueue
        self.myfilelock = lockfile
        self.myfilelocklast = lastlock

    def writeunchecked(self, hashindex):
        readindex = 0

        if os.path.exists(os.path.join('.', lastcheckedindexfile)):
            with open(lastcheckedindexfile, 'r') as fc:
                readindex = int(fc.readline().rstrip())

        with open(lastcheckedindexfile, 'w') as fw:
            if readindex == 0:
                fw.write(str(hashindex))
            elif readindex > hashindex:
                fw.write(str(hashindex))
            else:
                if hashindex - readindex > threadnum:
                    fw.write(str(hashindex))
                else:
                    fw.write(str(readindex))

    def run(self):
        while(True):
            # grap file hash from queue
            filehash_dict = self.myhashqueue.get()

            params = {'resource': filehash_dict.get("hash"),
                      'apikey': apikey}

            # send request to download file with the given hash
            checkdata = urllib.urlencode(params)
            checkrequest = urllib2.Request(reporturl, checkdata)

            try:
                checkresponse = urllib2.urlopen(checkrequest)
            except urllib2.URLError as e:
                if hasattr(e, 'reason'):
                    print 'Failed to reach server !'
                    print 'Reason: ', e.reason
                elif hasattr(e, 'code'):
                    print 'The server couldn\'t fulfill the request.'
                    print 'Error code: ', e.code
                else:
                    print "Unexpected connection error occured !"

                hashqueue.put(dict({"hash": filehash_dict.get("hash"), "index": filehash_dict.get("index")}))
            else:
                # check if limit has reached
                if checkresponse.getcode() == 204:
                    print 'Virustotal API request limit exceeded !'

                    self.myfilelocklast.acquire()
                    try:
                        self.writeunchecked(filehash_dict.get("index"))
                    finally:
                        self.myfilelocklast.release()

                    sys.exit(1)
                elif checkresponse.getcode() == 403:
                    print 'Not authorized privileged API functions called !'

                    self.myfilelocklast.acquire()
                    try:
                        self.writeunchecked(filehash_dict.get("index"))
                    finally:
                        self.myfilelocklast.release()

                    sys.exit(1)
                else:
                    responsejson = checkresponse.read()

                    # parse the json formatted VT response and add it to a dictionary
                    response_dict = simplejson.loads(responsejson)

                    # get the file hash from the VT response
                    filehash = response_dict.get("resource")
                    # get the code for detection from the VT response
                    isanalysed = response_dict.get("response_code")

                    # write VT check result to the file
                    if isanalysed == 1:

                        poscount = response_dict.get("positives")
                        # if it is detected by any AV scanners
                        if poscount == 0:

                            self.myfilelock.acquire()
                            try:
                                with open(outfile, 'a') as fw:
                                    fw.write(filehash + "\n")
                            finally:
                                self.myfilelock.release()

                    self.myhashqueue.task_done()

# read all hashes, get all distinct hashes and write them to a file
def readhashes():
    # starting line number to be read
    startline = 1

    if os.path.exists(os.path.join('.', lastcheckedindexfile)):
        with open(lastcheckedindexfile, 'r') as fc:
            line = fc.readline().rstrip()
            startline = int(line)

    with open(hashesfile, 'rU') as fo:
        # position in the file from where to start reading
        filestartpos = (startline - 1) * 34

        # move cursor to the starting position in file
        fo.seek(filestartpos, 0)

        for line in fo:
            if line.rstrip() != "":
                hashqueue.put(dict({'hash': line.rstrip(), 'index': startline}))
                startline += 1

# check the number of arguments entered
if len (sys.argv) == 1:
    print "Checkhashes-tt-notdetected.py executed.."
else:
    print "Usage: python checkhashes-tt-notdetected.py"
    sys.exit(1)

# lock to be used for file write operations
filelock = threading.Lock()
# lock to be used for writing remaining hashes after the limit is reached
filelocklast = threading.Lock()

readhashes()

# spawn a pool of threads specified in maxthreads
for i in range(threadnum):
    thread = ThreadVTCheck(hashqueue, filelock, filelocklast)
    thread.setDaemon(True)
    thread.start()

hashqueue.join()

sys.exit(1)
