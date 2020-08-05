import time
import struct

class Pcap:
    def __init__(self, filename):
        self.file = open(filename+".pcap",'wb')

        self.file.write(struct.pack('I',0xa1b2c3d4))
        self.file.write(struct.pack('H',2))
        self.file.write(struct.pack('H',4))
        self.file.write(struct.pack('i',0))
        self.file.write(struct.pack('I',0))
        self.file.write(struct.pack('I',65535))
        self.file.write(struct.pack('I',1))

    def write_data(self, data):
        ts = time.time()
        self.file.write(struct.pack('I',int(ts)))
        self.file.write(struct.pack('I',int(round(ts % 1 * 10 ** 6))))
        self.file.write(struct.pack('I',len(data)))
        self.file.write(struct.pack('I',len(data)))
        self.file.write(data)

    def close(self):
        self.file.close()