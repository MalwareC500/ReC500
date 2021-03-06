import hashlib
import os
import csv
import magic
import time

class Hasher:
    def __init__(self,filePath):
        self.filePath = filePath
    def compute(self):
        #print("+"*60)
        try:
            md5code = hashlib.md5(open(self.filePath, 'rb').read()).hexdigest()
            sha1code = hashlib.sha1(open(self.filePath, 'rb').read()).hexdigest()
        except:
            return None, None
        return md5code,sha1code

class CalMd5:
    def __init__(self, path):
        self.path = path
    def compute(self):
        global writercsv
        global dem
        for file in os.listdir(self.path):
            if os.path.isfile(self.path + "/" + file) == True:
                tstart = time.time()
                test = Hasher(self.path + "/" + file)
                (md5, sha1) = test.compute()
                tend = time.time()
                torigin = tend - tstart
                dem = dem + 1
                id = dem
                fname = file
                floca = self.path + "/" + file
                ftype = magic.from_file(self.path + "/" + file, mime=True)
                fsize = os.path.getsize(self.path + "/" + file)/(1024**2)
                datacsv = [[id, fname, md5, sha1, floca, None, ftype, fsize, torigin, None]]
                writercsv.writerows(datacsv)
                continue
            if os.path.isdir(self.path + "/" + file) == True:
                dirPath = self.path + "/" + file
                dp = CalMd5(dirPath)
                dp.compute()
                continue

if __name__ == "__main__":
    #whiteList = ['dlink', 'microtrain', 'openwrt', 'trendnet']
    dem = 0
    filename = "/home/malware/Documents/md5_atrung.csv"
    filecsv = open(filename, "w", newline = "")
    writercsv = csv.writer(filecsv, delimiter = ",")
    datacsv = [["ID", "Filename", "MD5", "SHA1", "FileLocation", "Note", "FileType", "Filesize", "TimeOrigin", "TimeCollect"]]
    writercsv.writerows(datacsv)
    for file in os.listdir("/home/malware/Documents/Ex_ReC500/"):
        if file != "cannotExtractFMK" and file.find(".csv") == -1 and file != "openwrte3000v1squashfsbin" and file != "FWE30001006002US20140409codebin":
            dirNeedToCal = "/home/malware/Documents/Ex_ReC500/" + file + "/extracted"
            print(dirNeedToCal)
            if os.path.isdir(dirNeedToCal):
                md5 = CalMd5(dirNeedToCal)
                md5.compute()
    print("Successfull!")
