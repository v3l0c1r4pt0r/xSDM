xSDM
====

Open-source unpacker for Microsoft's proprietary SDC format

Installation
------------

Just type make and program should build in current directory

Usage
-----
Program needs .sdc file as the only parameter. Decryption key should be placed in file named '$(sdcFileName).key'. Key file should be in same format as 'edv*' variable in Dreamspark's XML, that is 'crc+"^^"+fileNameKey+headerKey+xorKey', where crc and xorKey are decimal, 32-bit numbers.

More
----
You can find detailed instruction on how to download SDC file and find key on [my site](http://v3l0c1r4pt0r.tk/2014/06/01/how-to-download-from-dreamspark-bypassing-secure-download-manager/).
