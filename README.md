# Simple Nessus

Simple Nessus is a Ruby script that extracts only the most relevant information from [Tenable Nessus](http://www.tenable.com/products/nessus) reports.

It works with any proper .nessus (v2) file, even if the extension is changed. If you still need to work with v1 Nessus files, use the old Perl version of Simple Nessus, which can be found in previous commits of this project.


## Installation

Simple Nessus is developed on Ruby 1.9.3p194 and requires [Nokogiri](http://www.nokogiri.org/) and [Trollop](https://rubygems.org/gems/trollop). To install them, open the terminal and run

	gem install nokogiri
	gem install trollop


## Usage

To use Simple Nessus, run it as follows:

	ruby simple-nessus.rb -f {NESSUS-FILE} [OPTIONS]

The currently available options are:

	-v, --version 	Shows program version
	-h, --help 		Shows help

	-f <file> 		Set the input Nessus file to parse

	-s <severity> 	Set the minimum severity to extract
		-s A 	info, low, medium, high, critical
		-s L 	low, medium, high, critical (default)
		-s M 	medium, high, critical
		-s H 	high, critical

	-c <separator> 	Change the CSV output file separator (default ';')


Example:

	ruby simple-nessus.rb -f nessus-test-01.nessus -s M -c ,


## Copyright

Copyright (c) 2017 Giovanni Cattani

**Simple Nessus** is released under [The MIT License](http://www.opensource.org/licenses/mit-license.php).