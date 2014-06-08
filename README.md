xSDM
====

Open-source unpacker for Microsoft's proprietary SDC format

What is it?
-----------
xSDM is the program that unpacks from SDC (Secure Download Container) archive files. SDC is the format used by SDM (Secure Download Manager) - program needed to download from sites like MSDNAA/Dreamspark. It requires key file that can be gained by sniffing Dreamspark's transmission or using browser's developer tools.

Installation
------------

To compile the program you just need to issue standard
```
./configure
make
make install
```
where make install is optional. It will install xsdm into your system.

Usage
-----
Program needs .sdc file as the only parameter. Decryption key should be placed in file named '$(sdcFileName).key'. Key file should be in same format as 'edv*' variable in Dreamspark's XML, that is 'crc+"^^"+fileNameKey+headerKey+xorKey', where crc and xorKey are decimal, 32-bit numbers.

More
----
You can find detailed instruction on how to download SDC file and find key on [my site](http://v3l0c1r4pt0r.tk/2014/06/01/how-to-download-from-dreamspark-bypassing-secure-download-manager/).
