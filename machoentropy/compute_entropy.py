import sys
from macholib.MachO import MachO
from MachoEntropyComputer import MachoEntropyComputer

def processFile(filename):
    machoEntropyComputer = MachoEntropyComputer(filename, MachO(filename))
    for s in machoEntropyComputer.compute():
        print "%s has %i bytes with entropy of %f" % (s.sectionName, s.sectionSize, s.sectionEntropy)

def main(arguments):
    if len(arguments) != 2:
        print "Usage:", arguments[0], " MACHO_FILE"
    else:
        processFile(arguments[1])


if __name__ == "__main__":
    main(sys.argv)
