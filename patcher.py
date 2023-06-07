import r2pipe
import re

class cl:

    def __init__(self, File):
        self.File = File
        self.bytes = 6970612e636c617373706c75736170692e636f6d

    @property
    def check_arch(self):
        r2 = r2pipe.open(filename=f"{self.File}", flags=['-w','-2'])
        return (
            dict({
            "arch": re.findall("[\r\n\t\f\v ](.*m)", r2.cmd("iq"))[0],
            "r2bin": r2
        }))
        
class lib(cl):

    def __init__(self, File):
        super(lib, self).__init__(File)
        self.File = File
        self.r2 = self.check_arch["r2bin"]
        self.arch = self.check_arch["arch"]
        self.xrefs_addr = list()
  
    @property
    def patch(self):
        self.r2.cmd("aaa")
        print(f"{self.File.split('/')[-1]} architecture : {self.arch}")
        for main_addr in (re.findall("0x\S+", self.r2.cmd("fs symbols; f~Pin"))):
            self.xrefs_addr.append(self.r2.cmd(f'pd 1 @ {hex(eval(main_addr) + 20)}').split(';')[1].strip())
        for xrefs in self.xrefs_addr:
            print(f"patched successful @ {xrefs} {self.r2.cmd(f'wx {self.bytes} @ {xrefs}')}")

if __name__ == "__main__":
    import sys
    try:
        if sys.argv[1].endswith(".so"):
            libPath = sys.argv[1]
            lib(libPath).patch
        else:
            print("not a shared library")
            exit(1)
    except IndexError:
        print("Usage: python patcher.py <path>\r\n only for classplus api")