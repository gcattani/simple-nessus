#!/usr/bin/ruby

=begin
Simple Nessus v2.0 - Nessus files simplified
https://github.com/gcattani/simple-nessus

(c) 2015 Giovanni Cattani
Released under The MIT License
=end

require 'nokogiri'
require 'trollop'
require 'csv'

opts = Trollop::options do
  version "Simple Nessus v2.0"
  banner  "Simple Nessus v2.0\nhttps://github.com/gcattani/simple-nessus\n\nUsage:\n\t./simple-nessus.rb -f {FILE} [OPTIONS]\n\nOPTIONS:"

  opt :file, 'Nessus file to process',:type => String
  opt :severity, 'Minimum Severity Level: [A]ll, [L]ow, [M]edium, [H]igh, [C]ritical', :default => 'L'
  opt :col_sep, 'CSV Column Separator', :default => ';'
end

Trollop::die :file, "- please select a file to process" unless opts[:file]

doc = Nokogiri::XML(open(opts[:file]).read)

# MANAGE SEVERITY
if ['L', 'l', 'Low', 'low', 'LOW'].include? opts[:severity]
  arg_severity = 1
elsif ['M', 'm', 'Medium', 'medium', 'MEDIUM'].include? opts[:severity]
  arg_severity = 2
elsif ['H', 'h', 'High', 'high', 'HIGH'].include? opts[:severity]
  arg_severity = 3
elsif ['C', 'c', 'Critical', 'critical', 'CRITICAL'].include? opts[:severity]
  arg_severity = 4
else
  arg_severity = 0
end

output_file = opts[:file] + '_' + Time.now.to_s + '.csv'

CSV.open(output_file, 'wb', { col_sep: opts[:col_sep] }) do |csv|

  csv << ['IP Address', 'NetBIOS Name', 'FQDN', 'Severity', 'Risk Factor', 'Port', 'Protocol', 'Service', 'Plugin']

  doc.search('//ReportItem').each do |item|

	  severity = item.attr('severity').to_i

	  if (severity >= arg_severity)

	  	host_ip 	  = item.parent.xpath('HostProperties/tag[@name = "host-ip"]').text
	  	netbios_name  = item.parent.xpath('HostProperties/tag[@name = "netbios-name"]').text
	  	host_fqdn     = item.parent.xpath('HostProperties/tag[@name = "host-fqdn"]').text

		plugin_name   = item.attr('pluginName')
		svc_name      = item.attr('svc_name')
		protocol      = item.attr('protocol')
		port          = item.attr('port')

		if severity == 0
			risk_factor = 'Info'
		elsif severity == 1
			risk_factor = 'Low'
		elsif severity == 2
			risk_factor = 'Medium'
		elsif severity == 3
			risk_factor = 'High'
		elsif severity == 4
			risk_factor = 'Critical'
		end
	    
	    csv << [host_ip, netbios_name, host_fqdn, severity, risk_factor, port, protocol, svc_name, plugin_name]

	  end

  end

end