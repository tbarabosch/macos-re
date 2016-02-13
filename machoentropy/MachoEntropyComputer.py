import math
import collections

MachoEntropyInfo = collections.namedtuple('MachoEntropyInfo', 'sectionName sectionSize sectionEntropy')

class MachoEntropyComputer(object):

    def __init__(self, filename, macho):
        self.macho = macho
        self.filename = filename

    def _computeEntropyForSection(self, sectionData):
        # taken from http://rosettacode.org/wiki/Entropy#python
        log2=lambda x:math.log(x)/math.log(2)
        exr={}
        infoc=0
        for each in sectionData:
            try:
                exr[each]+=1
            except:
                exr[each]=1
        dataLen=len(sectionData)
        for k,v in exr.items():
            freq  =  1.0*v/dataLen
            infoc+=freq*log2(freq)
        infoc*=-1
        return infoc

    def _getSectionData(self, fileoff, filesize):
            f = open(self.filename, 'rb')
            f.seek(fileoff)
            data = f.read(filesize)
            f.close()
            return data

    def compute(self):
        res = []

        for (load_cmd, cmd, data) in self.macho.headers[0].commands:
            if hasattr(cmd, "segname"):

                segmentName = getattr(cmd, 'segname', '').rstrip('\0')
                sectionOffset = cmd.fileoff
                sectionSize = cmd.filesize
                if cmd.filesize > 0:
                    code = self._getSectionData(sectionOffset, sectionSize)
                    sectionEntropy = self._computeEntropyForSection(code)
                    res.append(MachoEntropyInfo(segmentName, sectionSize, sectionEntropy))

        return res




