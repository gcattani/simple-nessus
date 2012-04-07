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
} elsif ($output eq "M") {
	open MD, ">>", "simple-output.md";
} elsif ($output eq "C") {
	open CSV, ">>", "simple-output.csv";
	print CSV "host,vulnerability\n";
} elsif (!($output eq "O")) {
	die helper();
}

my $severity = sev_calc($sev_in);

##### Process the .nessus file
my $nessus = XMLin($nessusfile,
	ForceArray 	=> [ "ReportHost", "ReportItem", "tag" ],
	KeyAttr 	=> { tag => "PluginName" },
	ContentKey 	=> "-content",
);

##### Main Loop
my $report_name = $nessus->{Report}{"ReportName"};
print_name($output, $report_name);

my $report_host = $nessus->{Report}{ReportHost};

foreach my $host ( @$report_host ) {
	
	print_host($output, $host->{HostName});
		
	my $report_item = $host->{ReportItem};
	
	foreach my $item ( @$report_item ){
		if ( $item->{severity} >= $severity ) {
			print_vuln($output, $host->{HostName}, $item->{pluginName});
		}
		
	}
	
} # End of Main Loop


########## SUBROUTINES

##### Check for requested output and changes report name print style
# print_name($output, ReportName)
sub print_name(){
	my $print_check = $_[0]; # $output
	my $repo_name = $_[1];
	
	if ($print_check eq "O"){
		print "[#] ", $repo_name, "\n";
	} elsif ($print_check eq "T") {
		print TXT "[#] ", $repo_name, "\n";
	} elsif ($print_check eq "M") {
		print MD "# ", $repo_name, "\n";
	}
	# Not Affected: C
}

##### Checks for requested output and changes host name print style
# print_host($output, HostName);
sub print_host(){
	my $print_check = $_[0]; # $output
	my $host_name = $_[1];
	
	if ($print_check eq "O"){
		print "\n[*] ", $host_name, "\n";
	} elsif ($print_check eq "T") {
		print TXT "\n[*] ", $host_name, "\n";
	} elsif ($print_check eq "M") {
		print MD "\n### ", $host_name, "\n";
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
	} elsif ($print_check eq "M") {
		print MD "* ", "$host_vuln  \n";
	} elsif($print_check eq "C") {
		print CSV "$host_ip,$host_vuln\n";
	} else {
		die helper();	# This should never happen
	}

}

##### Converts severity in integers for easier usage
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

##### Prints usage information
sub helper(){
	print "\nSimple Nessus 0.5\nUsage: ./simple-nessus.pl {nessus-file} [SEVERITY] [OUTPUT]\n\nSEVERITY:\n  -s L: low, medium, high and critical\t(default)\n  -s M: medium, high and critical\n  -s H: high and critical\nOUTPUT:\n  -o O: STDOUT\t(default)\n  -o T: .txt\n  -o C: .csv\t[host-ip,vulnerability]\n  -o M: .md\n";
	exit;
}