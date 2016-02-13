import sys
import os
from collections import defaultdict
from macholib.MachO import MachO
from MachoEntropyComputer import MachoEntropyComputer

def processFile(filename):
    res = defaultdict()

    try:
        machoEntropyComputer = MachoEntropyComputer(filename, MachO(filename))
    except:
        print "ERROR while parsing", filename
        return None
    for s in machoEntropyComputer.compute():
        print "%s has %i bytes with entropy of %f" % (s.sectionName, s.sectionSize, s.sectionEntropy)
        res[s.sectionName] = s.sectionEntropy
    return res

def storeCsv(f, programName, data):
    f.write(programName + "," + str(data["__TEXT"]) + "," + str(data["__DATA"]) + "," + str(data["__LINKEDIT"]) + "\n")

def process(arg, csv=None):
    if os.path.isdir(arg):
        csvFile = None
        if csv:
            csvFile = open(csv, "w")

        fileList = os.listdir(arg)
        for f in fileList:
            print "Current program:", f
            res = processFile(os.path.join(arg, f))
            print "-" * 80

            if csvFile and res:
                storeCsv(csvFile, f, res)

        csvFile.close()
    else:
        processFile(arg)

def main(arguments):
    if len(arguments) != 2 and len(arguments) != 4:
        print "Usage:", arguments[0], "-csv CSVFILENAME MACHO_FILE/FOLDER_OF_MACHOs"
        print "-csv is optional. Stores results in csv file."
    elif len(arguments) == 2:
        process(arguments[1])
    else:
        process(arguments[3], csv=arguments[2])


if __name__ == "__main__":
    main(sys.argv)
