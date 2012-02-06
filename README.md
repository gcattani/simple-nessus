# Simple Nessus

**Simple Nessus** is a Perl script that aims to render [Tenable Nessus](http://www.tenable.com/products/nessus) reports more tidy by keeping only the relevant information.

It works with any proper .nessus file.

### Installation

**Simple Nessus** is developed on Perl v5.12.3 and requires _XML::Simple_ and _Getopt::Long_. To install them, open the terminal and run

	sudo cpan
	install XML::Simple
	install Getopt::Long


### Usage

To execute **Simple Nessus**, run it as follows:
	
	./simple-nessus.pl {nessus-file} [SEVERITY] [OUTPUT]

	SEVERITY:
	  -s L	low, medium and high	(default)
	  -s M	medium and high
	  -s H	high only
	

### Output 

The script supports several different outputs, detailed below.

1) STDOUT (default) and TXT (-o T):

	[*] Host_IP1
	Vulnerability_1
	Vulnerability_2

2) CSV (-o C):

	Host_IP1,Vulnerability1
	Host_IP1,Vulnerability2

### TO-DO

Upcoming features:

* "reverse" output (i.e. list of hosts for any vulnerability) 
* more control over final output


## Copyright

Copyright (c) 2012 Giovanni Cattani.

**Simple Nessus** is released under [The MIT License](http://www.opensource.org/licenses/mit-license.php).