xSDM
====

Open-source unpacker for Microsoft's proprietary SDC format

What is it?
-----------
xSDM is the program that unpacks from SDC (Secure Download Container) archive files. SDC is the format used by SDM (Secure Download Manager) - program needed to download from sites like MSDNAA/Dreamspark. It requires key file that can be gained by sniffing Dreamspark's transmission or using browser's developer tools.

Prerequisites
-------------
You need to have following packages in your system:
- zlib
- check >= 0.9.4
- libmcrypt

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

Issues
------
* There may be problem with make scripts that will tell you about wrong version of automake (or possibly that you don't have it). That problem could be solved by issuing autoreconf on the project's main dir (autotools are required for this).
* Program now cannot unpack cabinets with more than one file inside. It is due to the fact I couldn't find any (do they exist?). Nevertheless if you encounter one you are encouraged to contribute to the project by opening issue with debug message from the program.
* Any issue not described here should be reported on issues page on github.

More
----
You can find detailed instruction on how to download SDC file and find key on [my site](http://v3l0c1r4pt0r.tk/2014/06/01/how-to-download-from-dreamspark-bypassing-secure-download-manager/). There is also description of SDC file format ([here](http://v3l0c1r4pt0r.tk/2014/06/22/sdc-file-format-description-and-security-analysis-of-sdm/))
