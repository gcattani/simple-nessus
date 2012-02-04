#!/usr/bin/perl

# Simple Nessus - .nessus files simplified
#
# (c) 2012 Giovanni Cattani
# github.com/gcatt/simple-nessus
#
# Released under The MIT License

use strict;

use Getopt::Long;
use XML::Simple;


########## SIMPLE NESSUS

##### Defaults
my $sev_in = "L";
my $output = "O";

##### Options
my $nessusfile = $ARGV[0];

GetOptions (
			"severity=s" => \$sev_in,
			"output=s"   => \$output,
			help         => sub { helper(); }
) or die helper();

# Checks for correct $output parameters
if ($output eq "T") {
	open TXT, ">>", "simple-output.txt";
} elsif ($output eq "C") {
	open CSV, ">>", "simple-output.csv";
} elsif (!($output eq "O")) {
	die helper();
}

my $severity = sev_calc($sev_in);

##### Process .nessus file
my $nessus = XMLin($nessusfile,
	ForceArray 	=> [ "ReportHost", "tag" ],
	KeyAttr 	=> { tag => "name" },
	ContentKey 	=> "-content",
);

##### Main Loop
my $report_host = $nessus->{Report}{ReportHost};

foreach my $host ( @$report_host ) {
	
    my $properties = $host->{HostProperties}->{tag};

	print_host($output, $properties->{"host-ip"});
	
	my $report_item = $host->{ReportItem};
	
	foreach my $item ( @$report_item ){
		if ( $item->{severity} >= $severity ) {
			print_vuln($output, $properties->{"host-ip"}, $item->{pluginName});
		}
		
	}
	
} # End of Main Loop


########## SUBROUTINES

##### Checks for requested output and changes host IP print style
# print_host($output, host-ip);
sub print_host(){
	my $print_check = $_[0]; # $output
	my $host_ip = $_[1];
	
	if ($print_check eq "O"){
		print "\n[*] ", $host_ip, "\n";
	} elsif ($print_check eq "T") {
		print TXT "\n[*] ", $host_ip, "\n";
	}
	# Not Affected: C
}

##### Checks for requested output and changes vunerabilities print style
# print_vuln($output, host-ip, vulnerability);
sub print_vuln(){
	my $print_check = $_[0]; # $output
	my $host_ip = $_[1];
	my $host_vuln = $_[2];
	
	if ($print_check eq "O") {
		print "$host_vuln\n";
	} elsif ($print_check eq "T") {
		print TXT "$host_vuln\n";
	} elsif($print_check eq "C") {
		print CSV "$host_ip,$host_vuln\n";
	} else {
		die helper();
	}

}

##### Severity Calculator
# sev_calc($severity)
sub sev_calc(){
	my $sev_str = $_[0];
	
	if ($sev_str eq "L") {
		return 1;
	} elsif ($sev_str eq "M") {
		return 2;
	} elsif ($sev_str eq "H") {
		return 3;
	} else {
		die helper();
	}
}

##### Prints usage information (as seen below)
sub helper(){
	print "Simple Nessus 0.1\nUsage: ./simple-nessus.pl {nessus-file} [SEVERITY] [OUTPUT]\n\nSEVERITY:\n  -s L: low, medium and high\t(default)\n  -s M: medium and high\n  -s H: high only\nOUTPUT:\n  -o O: STDOUT\t(default)\n  -o T: .txt\t[same as STDOUT]\n  -o C: .csv\t[host-ip,vulnerability]\n";
	exit;
}

__END__

=head1 HELP

Simple Nessus 0.1
Usage: ./simple-nessus.pl {nessus-file} [SEVERITY] [OUTPUT]

SEVERITY:
  -s L	low, medium and high	(default)
  -s M	medium and high
  -s H	high only
OUTPUT
  -o O	STDOUT	(default)
  -o T	.txt	[same as STDOUT]
  -o C	.csv	[host-ip,vulnerability]

=cut