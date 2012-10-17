# Simple Nessus

**Simple Nessus** is a Perl script that aims to render [Tenable Nessus](http://www.tenable.com/products/nessus) reports more tidy by keeping only the relevant information.

It works with any proper .nessus (v1 and v2) file.

### Installation

**Simple Nessus** is developed on Perl v5.12.3 and requires _XML::Simple_ and _Getopt::Long_. To install them, open the terminal and run

	sudo cpan
	install XML::Simple
	install Getopt::Long


### Usage

To execute **Simple Nessus**, run it as follows:
	
	perl simple-nessus.pl {NESSUS-FILE} {VERSION} [SEVERITY] [OUTPUT] [OPTIONAL]

	VERSION:
	 -v1	.nessus v1 file
	 -v2	.nessus v2 file
	
	SEVERITY:
	  -s L:	low, medium, high and critical	(default)
	  -s M:	medium, high and critical
	  -s H:	high and critical
	
	OUTPUT
	  -o O:	STDOUT							(default)
	  -o T:	.txt file
	  -o C:	.csv file						[uses semicolon as separator]
	  -o M:	.md file
	
	OPTIONAL
	  -ports:	Show host port for each vulnerability

Example:

	perl simple-nessus.pl nessus-test-01.nessus -v1 -s H -o T -ports
	

## Copyright

Copyright (c) 2012 Giovanni Cattani.

**Simple Nessus** is released under [The MIT License](http://www.opensource.org/licenses/mit-license.php).