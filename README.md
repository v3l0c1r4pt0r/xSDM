xSDM
====

Open-source unpacker for Microsoft's proprietary SDC format

Installation
------------

Just type make and program should build in current directory

Usage
-----
Program need .sdc file as the only parameter. Decryption key should be placed in file named '$(sdcFileName).key'. Key file should be in same format as 'edv*' variable in Dreamspark's XML, that is 'crc+"^^"+fileNameKey+headerKey+xorKey'.
