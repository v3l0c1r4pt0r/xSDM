xSDM
====

Open-source unpacker for Microsoft's proprietary SDC format

What is it?
-----------
xSDM is the program that unpacks from SDC (Secure Download Container) archive
files. SDC is the format used by SDM (Secure Download Manager) - program needed
to download from sites like MSDNAA/Dreamspark. It requires key file that can be
gained by sniffing Dreamspark's transmission or using browser's developer tools.

Prerequisites
-------------
You need to have following packages in your system:
- zlib
- libmcrypt

On some distros these packages may be split into binaries and headers (like on
Debian-based systems). In this case you have to install packages named *-dev
(eg. libmcrypt-dev).

To do unit tests you also have to have check installed.

You should also have 64-bit Linux system (amd64). Any other configuration
(including MinGW and Mac OS X) may not work. There are few known errors that may
prevent you from correctly unpacing files on old 32-bit Linux systems. I am not
providing any support for more exotic systems.

Installation
------------

You are encouraged to use stable release instead of cloning master. Currently
the most stable release can be downloaded
[from here](https://github.com/v3l0c1r4pt0r/xSDM/releases/tag/v1.0.0). You
can also just clone repository and switch to v1.0.0 branch by typing
```git checkout v1.0.0```. If are experienced enough, you can use master
branch or even one of *-dev branches to test future enhancements.

To compile the program you just need to issue standard
```
./configure
make
make install
```
where make install is optional. It will install xsdm into your system.

Usage
-----
Program needs .sdc file as the only parameter. Decryption key should be placed
in file named '$(sdcFileName).key'. Key file should be in same format as 'edv*'
variable in Dreamspark's XML, that is 'crc+"^^"+fileNameKey+headerKey+xorKey',
where crc and xorKey are decimal, 32-bit numbers.

Issues
------
* Program now cannot unpack cabinets with more than one file inside. Support is
  now work in progress (follow issue #4 to get updates)
* The program is confirmed to work with SDC variants with the following header
  signatures: 0xb5, 0xd1. I'm in possession of variant 0xb3 and support for it
  will be added soon. If you have another variant of SDC file (especially 0xc4)
  I encourage you to send it to me so I will be able to write support for it.
* Any issue not described here should be reported on issues page on github.

More
----
You can find detailed instruction on how to download SDC file and find key on
[my site](http://v3l0c1r4pt0r.tk/2014/06/01/how-to-download-from-dreamspark-bypassing-secure-download-manager/).
There is also description of SDC file format
([here](http://v3l0c1r4pt0r.tk/2014/06/22/sdc-file-format-description-and-security-analysis-of-sdm/))
