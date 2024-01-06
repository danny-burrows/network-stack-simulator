
# https://stackoverflow.com/a/21001712
# https://web.archive.org/web/20190108202303/http://www.hackersdelight.org/hdcodetxt/crc.c.txt

def reverse(x):
   x = ((x & 0x55555555) <<  1) | ((x >>  1) & 0x55555555)
   x = ((x & 0x33333333) <<  2) | ((x >>  2) & 0x33333333)
   x = ((x & 0x0F0F0F0F) <<  4) | ((x >>  4) & 0x0F0F0F0F)
   x = (x << 24) | ((x & 0xFF00) << 8) | ((x >> 8) & 0xFF00) | (x >> 24)

   return x;

def crc32a(data):
    crc = 0xFFFFFFFF
    polynomial = 0x04C11DB7
    for byte in data:
        rv_byte =- reverse(byte)
        for _ in range(8):
            if int(crc ^ rv_byte) < 0:
                crc = (crc << 1) ^ 0x04C11DB7
            else:
                crc = (crc << 1)
    return reverse(~crc) & 0xFFFFFFFF

def crc32b(data):
    crc = 0xFFFFFFFF

    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xEDB88320
            else:
                crc = (crc >> 1)

    return crc ^ 0xFFFFFFFF


data = b"Hello, world!"

print(hex(crc32a(data)))
print(hex(crc32b(data)))
