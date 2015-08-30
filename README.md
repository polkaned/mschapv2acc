# mschapv2acc
MS-CHAP-V2 SHOULD NOT be used...

## What?
**mschapv2acc** is a proof of concept of MS-CHAP-V2 auditing/cracking tool.

It uses [old know vulnerability](https://www.schneier.com/paper-pptpv2.html) and fast implementation of cryptographic algorithm. The main goal is to show the need to change for other stronger protocol.

## So?
Just see...

### Standard mode
![std mode img](http://www.polkaned.net/benjo/mschapv2acc/sc1.png)

### Improved mode
![improved mode img](http://www.polkaned.net/benjo/mschapv2acc/sc2.png)

## Install
* You need a processor with SSE2 support.
* This tool can be compiled with gcc for Linux / Mac OS X.

Just extract the archive:
```
~$ tar xfvz mschapv2acc-x.y.z.tar.gz
~$ cd mschapv2acc-x.y.z
```

Or clone with git:
```
~$ git clone https://github.com/polkaned/mschapv2acc
~$ cd mschapv2acc
```

Or checkout with subversion:
```
~$ svn checkout --depth empty https://github.com/polkaned/mschapv2acc
~$ cd mschapv2acc
```

And execute 'make':
```
~$ make
```

## Features (or not)
* 2 main modes : Brute Force mode and Dictionary mode.
* To change the charset for the Brute Force mode, modify nbc and caract values in 'mschapv2acc.c' file in source code.

## Exemples of uses
* Brute force mode
```
~$ ./mschapv2acc file_auth
```
* Brute force mode with challenge's cryptanalysis enabled
```
~$ ./mschapv2acc -x file_auth
```
* Brute force mode with SSE2 enabled
```
~$ ./mschapv2acc -s file_auth
```
* Brute force mode with challenge's cryptanalysis and SSE2 enabled
```
~$ ./mschapv2acc -x -s file_auth
```
* Dictionary mode
```
~$ ./mschapv2acc -w dico.txt file_auth
```
* Dictionary mode with challenge's cryptanalysis enabled
```
~$ ./mschapv2acc -x -w dico.txt file_auth
```
All the options are listed on the help message printed when you run mschapv2acc with no parameter.

## About file_auth
file_auth is a binary dump file containing required MS-CHAP-V2 data.

This file is build as follow:
```
1 *int = user name length
user_name_lenght *char = user name
16 *unsigned char = auth challenge
16 *unsigned char = peer challenge
8 *unsigned char = challenge
24 *unsigned char = response
```

To get the file_auth:

* use my patch mschapCap4FR1.1.2.patch with this old [freeradius version](ftp://ftp.freeradius.org/pub/radius/old/freeradius-1.1.2.tar.gz). It puts the mschapv2acc file_auth in /tmp directory.
* use **wpe2acc** (included with mschapv2acc) for converting the [FreeRADIUS Wireless Pwnage Edition](http://www.willhackforsushi.com/FreeRADIUS_WPE.html) hex representation of MS-CHAP-V2 information to mschapv2acc file_auth.
* use [accgen.rb](https://gist.github.com/2472555) for converting John the Ripper input password file to mschapv2acc file_auth. Seems to be write for this tool: [Peap-Karma](https://github.com/phikshun/Peap-Karma) (relative [post](http://pulp-phikshun.blogspot.fr/2012/04/oh-wifi-how-broken-art-thee.html))

## Related stuff
### Paper
MS-CHAP-v2 et 802.11i, le mariage risqué ? [MISC 39](http://www.ed-diamond.com/produit.php?ref=misc39)
