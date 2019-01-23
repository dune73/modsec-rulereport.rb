#!/usr/bin/ruby
# vim: set expandtab shiftwidth=2 softtabstop=2:
#
# Copyright (C) 2015-2017 Christian Folini <folini@netnea.com>
# See below for license information
#
# This is a script that extracts ModSec alerts out of an apache error log and
# displays them in a terse report.
#
# The script is meant to be used together with the ModSecurity / Core Rule Set
# tuning methodology described at netnea.com.
#
# Multiple options exist to tailor the report. When trying to
# tune a modsecurity installation, the script can propose
# rule exclusions or directives for the apache configuration, which 
# can # be used to bypass the false positives reported by the script.
#
# Call with the option --help to get an usage overview.
#
# TODO / FIXME
# - Import Error-Log from file
# - function tests
# - List tag mode
# - Select tags
# - Handle rules where variables should be updated instead of exclusion rules 
# - Baserule id: pass baserule ID via command line
# - Make sure all alert message types are understood and parsed
#   This depends on the operator
#   List of operators:
#   - rx
#   - streq
#   - ...
# - default values for startup<->runtime, rule<->target, id<->tag<->msg
# - env values for startup<->runtime, rule<->target, id<->tag<->msg
# - Baserule id: Save final rule ID in file. Load from file the next time per default.
# - Baserule id: get baserule ID from env variable
# - Indicate PL with rule ids in comments
# - Option to limit width of rule output. Line break
# - change sort order of rules
# - new interface: new modes
#   - selector (->only with runtime)
#     - path (+ optional: number of pathsegments)
#     - method
#     - user-agent
#     - referer
#     - selectors should be stackable
# - Support for audit log
# - Support for raw e
# - Force flag to override the special handling of rules where a variable should be reconfigured
#   But do a standard rule exclusion instead
# - check all function descriptions (key items like input/output/return-value)
# - support for alerts of whitelisting rules (Match of ... required)
# - mockup tests of script
#
# --------------------------------------------------------------------------------------
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; version 3
# of the License only.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to 
# Free Software Foundation, 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
#
# --------------------------------------------------------------------------------------
#

# -----------------------------------------------------------
# INIT
# -----------------------------------------------------------

require "optparse"
require "date"
require "pp"
require 'open-uri'
require "rubygems"

params = Hash.new

params[:verbose] = false
params[:debug]   = false

MODE_STARTTIME = 1
MODE_RUNTIME = 2

RTMODE_RULE = 1
RTMODE_TARGET = 2

BY_ID = 1
BY_TAG = 2
BY_MSG = 3

RULEID_DEFAULT = 10000

params[:filenames] = Array.new
params[:ruleid] = RULEID_DEFAULT

Severities = {
	"NOTICE" => 2,
	"WARNING" => 3,
	"ERROR" => 4,
	"CRITICAL" => 5
}

class Event
	attr_accessor :id, :unique_id, :ip, :msg, :uri, :parameter, :hostname, :file, :tags

	def initialize(id, unique_id, ip, msg, uri, parameter, hostname, file, tags)
		@id = id
		@unique_id = unique_id
		@ip = ip
		@msg = msg
		@uri = uri
		@parameter = parameter
		@hostname = hostname
		@file = file
		@tags = tags
	end
end


# -----------------------------------------------------------
# SUB-FUNCTIONS (those that are specific to this script)
# -----------------------------------------------------------

def import_files(filenames, params)
  # Purpose: Import files
  # Input  : filename array
  # Output : none
  # Return : events array
  # Remarks: none

  events = Array.new()

  begin

    unless (check_stdin())

      filenames.each do |filename|

        File.open(filename, "r") do |file|

      	  vprint("Reading file #{filename} ...", params)
	  events.concat(read_file(file, params))

	end

      end

    else

      	vprint("Reading STDIN ...", params)
	events.concat(read_file(STDIN, params))

    end

  rescue Errno::ENOENT => detail
    puts_error("File could not be opened. This is fatal. Aborting.", detail)
    exit 1
  rescue => detail
    puts_error("Unknown error during file read. This is fatal. Aborting.", detail)
    exit 1
  end

  return events

end

def parse_event_from_string(str, params)
  # Purpose: Wrap read_file so that a string can be passed
  # Input  : string, params
  # Output : none
  # Return : events array
  # Remarks: none

  file = StringIO.new(str)
  events =  read_file(file, params)
  file.close
  return events

end

def read_file(file, params)
  # Purpose: Read file
  # Input  : file handle
  # Output : none
  # Return : events array
  # Remarks: none

  events = Array.new()

  def scan_line (line, key, default, params)
    begin
      return line.scan(/\[#{key} \"([^"]*)\"/)[0][0]
    rescue
      return default
    end
  end
  def scan_line_tags (line, params)
    tags = Array.new
    begin
    	line.split("[tag ").each do |item|
		if not /\[/.match(item)
			item.gsub!(/\].*/, "").gsub!(/"/, "")
			dprint("Identified tag #{item}", params)
			tags << item
		end
	end
      return tags
    rescue => detail
      puts_error("Problem parsing tags on input line: #{line}", detail)
      return tags
    end
  end

  while ! file.eof?
	line = file.readline
	if /ModSecurity: (Warning|Access denied.*)\. /.match(line)

	  # standard parameters
          id = scan_line(line, "id", "0", params)
          unique_id = scan_line(line, "unique_id", "no-id-found", params)
          msg = scan_line(line, "msg", "none", params)
	  uri = scan_line(line, "uri", "/", params)
	  hostname = scan_line(line, "hostname", "unknown", params)
	  eventfile = scan_line(line, "file", "none", params)
	  tags = scan_line_tags(line, params)


	  # custom parameters
	  begin
	    ip = line.scan(/\[client ([^\]]*)\]/)[0][0]
	  rescue
	    ip = "0.0.0.0"
	  end

	  begin

	  if /ModSecurity: (Warning.|Access denied with.*) (Pattern match|Matched phrase)/.match(line)
		    # Operators: pm, pmFromFile, strmatch, rx
	    	    # example: standard operator results in:  ModSecurity: Warning. Pattern match "^[\\\\d.:]+$" at REQUEST_HEADERS:Host.
		    parameter = line.scan(/ (at|against) "?(.*?)"?( required)?\. \[file \"/)[0][1]

	  elsif /ModSecurity: (Warning.|Access denied with.*) detected (SQLi|XSS) using libinjection/.match(line)
		    # Operators: detectSQLi, detectXSS
	    	    # example: ModSecurity: Warning. detected SQLi using libinjection with fingerprint 's&1' [file ...  [data "Matched Data:  found within ARGS:sqli: ' or 1=1"] 
		    # The detectSQLi / detectXSS operator do not report the affected parameter by itself. Instead we need to fetch the parameter out of the logdata field. 
		    # This only works when the logdata format is consistent.
		    # Right now, we use the format defined in CRS3 rule 942100.
		    parameter = line.scan(/\[data "Matched Data:.*found within ([^ ]*): /)[0][0]

	  elsif /ModSecurity: (Warning.|Access denied with.*) String match/.match(line)
		    # Operators: beginsWith, contains, containsWord, endsWith, streq, within
	    	    # example: ModSecurity: Warning. String match "/" at REQUEST_URI. [file ...] 
	    	    # example: ModSecurity: Warning. String match within "GET POST" at REQUEST_METHOD. [file ...]
		    parameter = line.scan(/String match (within )?".*" at (.*?)\. \[file /)[0][1]

	  elsif /ModSecurity: (Warning.|Access denied with.*) Operator [A-Z][A-Z] matched/.match(line)
		    # Operators: eq, ge, gt, le, lt
	    	    # example: ModSecurity: Warning. Operator EQ matched 1 at ARGS. [file ...]
		    parameter = line.scan(/Operator [A-Z][A-Z] matched .* at ([^ ]*)\. \[file /)[0][0]

	  elsif /ModSecurity: (Warning.|Access denied with.*) IPmatch(FromFile)?: ".*" matched at/.match(line)
		    # Operators: ipMatch, ipMatchFromFile
	    	    # example: ModSecurity: Warning. IPmatch: "127.0.0.1" matched at REMOTE_ADDR.
		    parameter = line.scan(/IPmatch(FromFile)?: "[^"]*" matched at ([^ ]*)\. \[file /)[0][1]

	  elsif /ModSecurity: (Warning.|Access denied with.*) Unconditional match in SecAction/.match(line)
		    # Operators: unconditionalMatch
	    	    # example: ModSecurity: Warning. Unconditional match in SecAction. [file ...]
		    # The unconditionalMatch operator does not report the parameter that was involved in the rule
		    # One would need to get it out of the logdata entry of the alert, but there is no
		    # standard way of configuring that, so there is no convention to base ourselves upon.
		    # Given the use of @unconditionalMatch is very rare,
		    # we set the parameter to "UNKNOWN"
		    parameter = "UNKNOWN"

	  elsif /ModSecurity: (Warning.|Access denied with.*) Found \d+ byte\(s\) in .* outside range:/.match(line)
		    # Operators: validateByteRange
	    	    # example: ModSecurity: Warning. Found 9 byte(s) in REMOTE_ADDR outside range: 0. [file ... ]
		    parameter = line.scan(/Found \d+ byte\(s\) in ([^ ]*) outside range: /)[0][0]

	  elsif /ModSecurity: (Warning.|Access denied with.*) Match of ".*" against ".*" required\./.match(line)
		    # Operators: All negated operators (-> "!@xxx ...")
	    	    # example: ModSecurity: Warning. Match of "rx ^(abc)$" against "ARGS:a" required. [file
		    parameter = line.scan(/ against "([^ ]*)" required\. \[file /)[0][0]

	  else
  		$stderr.puts "ERROR: Could not interpret alert message. Ignoring message: #{line}"

	    end
	  rescue => detail
            puts_error("Error parsing alert message. This is fatal. Bailing out. Alert message: #{line}", detail)
	    exit 1
	  end

	  events << Event.new(id, unique_id, ip, msg, uri, parameter, hostname, eventfile, tags)

        end
  end

  return events
	
end

def build_uri_list(id, events) 
  # Purpose: build an array of URIs out of an event list filtered for given rule id
  # Input  : rule id, events array
  # Output : array with URIs
  # Return : none
  # Remarks: none
  # Tests:   none
        
      uris = Array.new
      events.select{|h| h.id == id }.each do |h|
      	if uris.grep(h.uri).length == 0 
      		uris << h.uri
      	end
      end

      uris.sort!{|x,y| x <=> y }
	
      return uris

end

def build_parameter_list(id, events)
  # Purpose: build an array of parameters out of an event list filtered for given rule id
  # Input  : rule id, event object, events array
  # Output : parameter array
  # Return : none
  # Tests:   none

	parameters = Array.new
	events.select{|h| h.id == id }.each do |h|
		if parameters.grep(h.parameter).length == 0 
			parameters << h.parameter
		end
	end
	parameters.sort!{|x,y| x <=> y }

	return parameters
end

def build_target_uri_list(id, events, params)
  # Purpose: build an array of parameters and paths out of an event list filtered for given rule id
  # Purpose: Build a list of path items
  # Input  : rule id, events array
  # Output : none
  # Return : array with items
  # Remarks: none
  # Tests:   none

	items = Array.new
	
	dprint("Building list with paths and parameters for this rule / event id:", params)
	
	events.select{|e| e.id == id }.each do |e|
		if e.parameter != ""
			num = items.select{|tuple| tuple[:parameter] == e.parameter && tuple[:uri] == e.uri}.length
			if num == 0
				tuple = Hash.new
				tuple[:parameter] = e.parameter
				tuple[:uri] = e.uri
				tuple[:num] = 1
				dprint("  Creating new tuple with parameter #{tuple[:parameter]} and uri #{tuple[:uri]}", params)
				items << tuple
			else
				tuple = items.select{|tuple| tuple[:parameter] == e.parameter && tuple[:uri] == e.uri}[0]
				dprint("  Raising number of occurrence of tuple with parameter #{tuple[:parameter]} and uri #{tuple[:uri]} to #{tuple[:num] + 1}", params)
				tuple[:num] = tuple[:num] + 1
			end
		else
			dprint("  No argument found in event. Event can thus not be handled in this mode. Passing to next event.", params)
		end
	end

	items.sort!{|x,y| x[:parameter] <=> y[:parameter] }
	if params[:debug]
		puts "Items/tuples to be used for ignore rule with id #{id}:"
		pp items
	end

	return items

end

def display_individual_uris(id, uris, events, params)
  # Purpose: print a list of uris out of a list of events, filtered by a rule id
  # Input  : rule id, uri array, events array
  # Output : report via stdout
  # Return : none
  # Remarks: none
  # Tests:   0100-startup-rule-byid.test OK

	str = ""

	str += "\n"
	str += "      Individual paths:\n"
	uris.each do |uri|
		num = events.select{|h| h.id == id && h.uri == uri}.length

		hostnames = Array.new
		events.select{|h| h.id == id and h.uri == uri}.each do |h|
			if hostnames.grep(h.hostname).length == 0
				hostnames << h.hostname
			end
		end

		if hostnames.length > 1
			str += sprintf "  %6d %s\t(multiple services: %s)\n", num.to_s, uri, hostnames.join(" ")
		else
			str += sprintf "  %6d %s\t(service %s)\n", num.to_s, uri, hostnames[0]
		end
	end

	return str

end

def display_rule_exclusion_startup_rule_byid(id, event, events, params)
  # Purpose: print startup rule exclusion for rule selected by rule id
  # Input  : rule id, event object, events array
  # Output : report via stdout
  # Return : none
  # Remarks: none
  # Tests:   0100-startup-rule-byid.test OK

  	str = ""

	str += "      # ModSec Rule Exclusion: #{event.id} : #{event.msg}\n"
	str += "      SecRuleRemoveById #{event.id}\n"

	return str
	
end

def display_rule_exclusion_startup_rule_bytag(id, event, events, params)
  # Purpose: print startup rule exclusion for rules selected by rule tag
  # Input  : rule id, event object, events array
  # Output : report via stdout
  # Return : none
  # Remarks: none
  # Tests:   0105-startup-rule-bytag.test OK

  	str = ""

        event.tags.each do |tag|
		str += "      # ModSec Rule Exclusion : #{event.id} via tag \"#{tag}\" (Msg: #{event.msg})\n"
		str += "      SecRuleRemoveByTag #{escape_tag(tag)}\n"
		str += "\n"
	end

	return str
	
end

def display_rule_exclusion_startup_rule_bymsg(id, event, events, params)
  # Purpose: print startup rule exclusion for rule selected by rule msg
  # Input  : rule id, event object, events array
  # Output : report via stdout
  # Return : none
  # Remarks: none
  # Tests:   0110-startup-rule-bymsg.test OK

  	str = ""

	str += "      # ModSec Rule Exclusion: #{event.id} : #{event.msg}\n"
	str += "      SecRuleRemoveByMsg \"#{event.msg}\"\n"
	str += "\n"

	return str
	
end

def display_rule_exclusion_startup_target_byid(id, event, events, params)
  # Purpose: print startup rule exclusion for specific parameter in rule selected by rule id
  # Input  : rule id, event object, events array
  # Output : report via stdout
  # Return : none
  # Tests:   0130-startup-target-byid.test OK

  	str = ""

	parameters = build_parameter_list(id, events)

	if parameters.length == 0 or ( parameters.length == 1 and parameters[0] == "" )
		str += "      No parameter available to create ignore-rule proposal.\n"
	else
		str += "      # ModSec Rule Exclusion: #{id} : #{event.msg}\n"

		parameters.each do |parameter|
			num = events.select{|h| h.id == id && h.parameter == parameter}.length
			if parameter != ""
				str += sprintf "      SecRuleUpdateTargetById %6d \"!%s\"\n", id, parameter
			end
		end
	end

	return str

end

def display_rule_exclusion_startup_target_bytag(id, event, events, params)
  # Purpose: print startup rule exclusion for specific parameter in rules selected by tag
  # Input  : rule id, event object, events array
  # Output : report via stdout
  # Return : none
  # Remarks: none
  # Tests:   0135-startup-target-bytag.test OK

  	str = ""

	parameters = build_parameter_list(id, events)

	if parameters.length == 0 or ( parameters.length == 1 and parameters[0] == "" )
		str += "      No parameter available to create ignore-rule proposal.\n"
	else

        	event.tags.each do |tag|

			str += "      # ModSec Rule Exclusion: #{id} via tag #{tag}: (Msg: #{event.msg})\n"

			parameters.each do |parameter|
				num = events.select{|h| h.id == id && h.parameter == parameter}.length
				if parameter != ""
						str += "      SecRuleUpdateTargetByTag #{escape_tag(tag)} \"!#{parameter}\"\n"
				end
			end

			str += "\n"

		end
	end

	return str
end

def display_rule_exclusion_startup_target_bymsg(id, event, events, params)
  # Purpose: print startup rule exclusion for specific parameter in rule selected by msg
  # Input  : rule id, event object, events array
  # Output : report via stdout
  # Return : none
  # Remarks: none
  # Tests:   0140-startup-target-bymsg.test OK

  	str = ""

	parameters = build_parameter_list(id, events)

	if parameters.length == 0 or ( parameters.length == 1 and parameters[0] == "" )
		str += "      No parameter available to create ignore-rule proposal.\n"
	else

		str += "      # ModSec Rule Exclusion: #{event.id} : #{event.msg})\n"

		parameters.each do |parameter|
			num = events.select{|h| h.id == id && h.parameter == parameter}.length
			if parameter != ""
					str += "      SecRuleUpdateTargetByMsg \"#{event.msg}\" \"!#{parameter}\"\n"
			end
		end

		str += "\n"

	end

	return str

end



def display_rule_exclusion_runtime_rule_byid(id, event, events, params)
  # Purpose: print runtime rule exclusion for rule selected by rule id
  # Input  : rule id, event object, events array
  # Output : report via stdout
  # Return : none
  # Remarks: proposed exclusion rule uses the first URI in the list. Additional uris are listed separately. 
  #          This can be re-considered at a later moment
  # Tests:   0150-runtime-rule-byid.test OK

  	str = ""

	uris = build_uri_list(id, events)

	str += "      # ModSec Rule Exclusion: #{id} : #{event.msg}\n"
	str += "      SecRule REQUEST_URI \"@beginsWith #{uris[0]}\" \"phase:1,nolog,pass,id:#{params[:ruleid]},ctl:ruleRemoveById=#{id}\"\n"

	params[:ruleid] = params[:ruleid] + 1

	str += display_individual_uris(id, uris, events, params)

	return str

end

def display_rule_exclusion_runtime_rule_bytag(id, event, events, params)
  # Purpose: print runtime rule exclusion for rules selected by rule tag
  # Input  : rule id, event object, events array
  # Output : report via stdout
  # Return : none
  # Remarks: This displays multiple variants based on individual tags of the same event
  #          Proposed exclusion rule uses the first URI in the list. Additional uris are listed separately. 
  #          This can be re-considered at a later moment
  # Tests:   0155-runtime-rule-bytag.test OK
	
	str = ""

	uris = build_uri_list(id, events)

        event.tags.each do |tag|
		str += "      # ModSec Rule Exclusion : #{event.id} via tag \"#{tag}\" (Msg: #{event.msg})\n"
		str += "      SecRule REQUEST_URI \"@beginsWith #{uris[0]}\" \"phase:1,nolog,pass,id:#{params[:ruleid]},ctl:ruleRemoveByTag=#{escape_tag(tag)}\"\n"
		str += "\n"
	end

	str += display_individual_uris(id, uris, events, params)

	return str

end

def display_rule_exclusion_runtime_rule_bymsg(id, event, events, params)
  # Purpose: print runtime rule exclusion for rule selected by rule msg
  # Input  : rule id, event object, events array
  # Output : report via stdout
  # Return : none
  # Remarks: none
  # Tests:   0160-runtime-rule-bymsg.test OK

  	str = ""

	uris = build_uri_list(id, events)

	uris.sort!{|x,y| x <=> y }
	str += "      # ModSec Rule Exclusion: #{id} : #{event.msg}\n"
	str += "      SecRule REQUEST_URI \"@beginsWith #{uris[0]}\" \"phase:1,nolog,pass,id:#{params[:ruleid]},ctl:ruleRemoveByMsg=#{escape_msg(event.msg)}\"\n"
	params[:ruleid] = params[:ruleid] + 1

	str += display_individual_uris(id, uris, events, params)

	return str

end


def display_rule_exclusion_runtime_target_byid(id, event, events, params)
  # Purpose: print runtime rule exclusion for specific parameter in rule selected by rule id
  # Input  : rule id, event object, events array
  # Output : report via stdout
  # Return : none
  # Remarks: none
  # Tests:   0180-runtime-target-byid.test OK

  	str = ""

	str += "      # ModSec Rule Exclusion: #{id} : #{event.msg}\n"

        items = build_target_uri_list(id, events, params)

	if items.length == 0 or ( items.length == 1 and items[0] == "" )
		str += "  No parameter available to create ignore-rule proposal. Please try and use different mode.\n"
	else
		items.each do |tuple|
				prefix = ""
				if params[:verbose]
					prefix = tuple[:num].to_s + " x"
				end
				str += sprintf "     %s SecRule REQUEST_URI \"@beginsWith %s\" \"phase:2,nolog,pass,id:%d,ctl:ruleRemoveTargetById=%d;%s\"\n", prefix, tuple[:uri], params[:ruleid], id, tuple[:parameter]
				params[:ruleid] = params[:ruleid] + 1

		end
	end

	return str
 
end

def display_rule_exclusion_runtime_target_bytag(id, event, events, params)
  # Purpose: print runtime rule exclusion for specific parameter in rules selected by rule tag
  # Input  : rule id, event object, events array
  # Output : report via stdout
  # Return : none
  # Remarks: This displays multiple variants based on individual tags of the event
  # Tests:   0185-runtime-target-bytag.test OK

  	str = ""

	parameters = Array.new
	events.select{|h| h.id == id }.each do |h|
		if parameters.grep(h.parameter).length == 0 
			parameters << h.parameter
		end
	end
	parameters.sort!{|x,y| x <=> y }

        items = build_target_uri_list(id, events, params)

	if parameters.length == 0 or ( parameters.length == 1 and parameters[0] == "" )
		str += "  No parameter available to create ignore-rule proposal. Please try and use different mode.\n"
	else
		items.each do |tuple|

			event.tags.each do |tag|

				str += "      # ModSec Rule Exclusion: #{id} via tag #{tag}: (Msg: #{event.msg})\n"

				parameters.each do |parameter|
					num = events.select{|h| h.id == id && h.parameter == parameter}.length
					if parameter != ""
							str += sprintf "      SecRule REQUEST_URI \"@beginsWith %s\" \"phase:2,nolog,pass,id:%d,ctl:ruleRemoveTargetByTag=%s;%s\"\n", tuple[:uri], params[:ruleid], escape_tag(tag), tuple[:parameter]
					end
				end
				str += "\n"
			end
			params[:ruleid] = params[:ruleid] + 1
		end
	end

	return str

end

def display_rule_exclusion_runtime_target_bymsg(id, event, events, params)
  # Purpose: print runtime rule exclusion for specific parameter in rule selected by msg
  # Input  : rule id, event object, events array
  # Output : report via stdout
  # Return : none
  # Remarks: none
  # Tests:   0190-runtime-target-bymsg.test OK

  	str = ""

	str += "      # ModSec Rule Exclusion: #{id} : #{event.msg}\n"
        
	items = build_target_uri_list(id, events, params)

	if items.length == 0 or ( items.length == 1 and items[0] == "" )
		str += "  No parameter available to create ignore-rule proposal. Please try and use different mode.\n"
	else
		items.each do |tuple|

				prefix = ""
				if params[:verbose]
					prefix = tuple[:num].to_s + " x"
				end
				str += sprintf "     %s SecRule REQUEST_URI \"@beginsWith %s\" \"phase:2,nolog,pass,id:%d,ctl:ruleRemoveTargetByMsg=%s;%s\"\n", prefix, tuple[:uri], params[:ruleid], escape_msg(event.msg), tuple[:parameter]
				params[:ruleid] = params[:ruleid] + 1

		end
	end

	return str

end



def display_report(events, params)
  # Purpose: display report
  # Input  : events array
  # Output : report via stdout
  # Return : none
  # Remarks: none

  str = ""

  vprint("Displaying report ...", params)

  ids = Array.new
  dprint("Building list of relevant ids (that is the ids we will covering, this is not the same as the list of events):", params)
  events.each do |event|
		if ids.grep(event.id).length == 0 && 
			( event.id != "981176" && event.id != "981202" && event.id != "981203" && event.id != "981204" && event.id != "981205" && event.id != "949110" && event.id != "959100" && event.id != "980100" && event.id != "980110" && event.id != "980120" && event.id != "980130" && event.id != "980140") 
			# 981203/4/5 are the rules checking anomaly score in the end on CRS2. Ignoring those
			# 949110, 959100 and 980100ff are the rules checking anomaly score in the end on CRS3. Ignoring those
			dprint("  Adding event id #{event.id}", params)
			ids << event.id
		else
			# id is already part of id list
			dprint("  Ignoring event id #{event.id}", params)
		end
  end
  ids.sort!{|a,b| a <=> b }
  
  ids.each do |id|
        dprint("\nLoop over event ids (id = #{id}):", params)
	event = events.find {|e| e.id == id }
	len = events.select{|e| e.id == id }.length

	case params[:sr]
	when MODE_STARTTIME
		case params[:rt] 
		when RTMODE_RULE
			case params[:ruleselector]
			when BY_ID
			    	# SecRuleRemoveById

				str += display_rule_exclusion_startup_rule_byid(id, event, events, params)

			when BY_TAG
				# SecRuleRemoveByTag"

				str += display_rule_exclusion_startup_rule_bytag(id, event, events, params)

			when BY_MSG
				# SecRuleRemoveByMsg"

				str += display_rule_exclusion_startup_rule_bymsg(id, event, events, params)

			end

		when RTMODE_TARGET
			case params[:ruleselector]
			when BY_ID
				# SecRuleUpdateTargetById

				str += display_rule_exclusion_startup_target_byid(id, event, events, params)

			when BY_TAG
				# SecRuleUpdateTargetByTag

				str += display_rule_exclusion_startup_target_bytag(id, event, events, params)

			when BY_MSG
				# SecRuleUpdateTargetByMsg"

				str += display_rule_exclusion_startup_target_bymsg(id, event, events, params)

			end
		end
	when MODE_RUNTIME
		case params[:rt] 
		when RTMODE_RULE
			case params[:ruleselector]
			when BY_ID
				# SecRule ... ctl:ruleRemoveById

				str += display_rule_exclusion_runtime_rule_byid(id, event, events, params)

			when BY_TAG
				
				# SecRule .... ctl:ruleRemoveByTag

				str += display_rule_exclusion_runtime_rule_bytag(id, event, events, params)

			when BY_MSG
				# SecRule ... ctl:ruleRemoveByMsg

				str += display_rule_exclusion_runtime_rule_bymsg(id, event, events, params)

			end

		when RTMODE_TARGET
			case params[:ruleselector]
			when BY_ID
				# SecRule ... ctl:ruleRemoveTargetById

				str += display_rule_exclusion_runtime_target_byid(id, event, events, params)

			when BY_TAG
				# SecRule ... ctl:ruleRemoveTargetByTag

				str += display_rule_exclusion_runtime_target_bytag(id, event, events, params)

			when BY_MSG
				# SecRule ... ctl:ruleRemoveTargetByMsg"

				str += display_rule_exclusion_runtime_target_bymsg(id, event, events, params)

			end
		end
	end
  end

  return str 

end

def escape_tag(item)
  # Purpose: Escape the "/" charcter in tags
  # Input  : string
  # Output : string
  # Return : none
  # Remarks: none
  
  return item.gsub(/\//, "\\/")

end

def escape_msg(item)
  # Purpose: Replace space chars with dots
  # Input  : string
  # Output : string
  # Return : none
  # Remarks: none
  
  return item.gsub(/\//, "\\/").gsub(/\ /, ".")

end


			


# -----------------------------------------------------------
# GENERIC SUB-FUNCTIONS (those that come with every script)
# -----------------------------------------------------------
#
def dump_parameters(params)
  # Purpose: Display parameters
  # Input  : Parameter Hash
  # Output : Dump parameters to stdout
  # Return : none
  # Remarks: none
  
  str = ""
  str += "Parameter overview"
  str += "------------------"
  str += "verbose    : #{params[:verbose]}"
  unless check_stdin()
  	str += "files           : #{params[:filenames].each do |x| x ; end}"
  else
  	str += "files      : [STDIN]"
  	str += "startup/runtime : #{params[:sr]}"
  	str += "rule/target     : #{params[:rt]}"
  	str += "byid/tag/msg    : #{params[:ruleselector]}"
  end

  return str

end

def vprint(text, params)
  # Purpose: output text if global variable $verbose is set.
  # Input  : String input
  # Output : stdout
  # Remarks: none

  if params[:verbose]
    puts text
  end

end

def dprint(text, params)
  # Purpose: output text if global variable $debug is set.
  # Input  : String input
  # Output : stdout
  # Remarks: none
  
  if params[:debug]
    puts text
  end

end

def check_stdin ()
  # Purpose: Check for access to STDIN
  # Input  : none
  # Output : bool
  # Remarks: none

  if STDIN.tty?
    # no stdin
    return false
  else
    # stdin
    return true
  end

end

def check_parameters(params)
  # Purpose: check parameters
  # Input  : global variable params
  # Output : stderr in case there is a problem with one of the parameters
  # Return : true if there is an error with one of the parameters; or false in absence of errors
  # Remarks: None

  err_status = false

  unless params[:ruleid] > 0
   $stderr.puts "Error in ruleid parameter (#{params[:ruleid]}). Has to be an integer above 0. This is fatal. Aborting."
   err_status = true
  end
  
  return err_status
  
end

def puts_error(msg, detail)
  # Purpose: Print error message
  # Input  : string msg and detail exception object
  # Output : $stderr
  # Return : None
  # Remarks: There is a ruby exception class hierarchy. 
  #          See http://makandracards.com/makandra/4851-ruby-exception-class-hierarchy

  err_status = false
  $stderr.puts msg
  $stderr.puts "Error: #{detail.message}" if detail
  $stderr.puts "Backtrace:" if detail
  $stderr.puts detail.backtrace.join("\n") if detail
  $stderr.puts "--------------------------"

end

# -----------------------------------------------------------
# COMMAND LINE PARAMETER EXTRACTION
# -----------------------------------------------------------
#

# -----------------------------------------------------------
# MAIN
# -----------------------------------------------------------

def main(params)

begin

parser = OptionParser.new do|opts|
  opts.banner = <<EOF
  
  #{File.basename(__FILE__)}

  A script that extracts ModSec alert messages out of an apache error log and
  proposes exclusion rules to make the supposed false positives disappear.

  The script is meant to be used together with the ModSecurity / Core Rule Set
  tuning methodology described at https://netnea.com. There is also a
  ModSecurity tuning cheatsheet at netnea.com that illustrates the
  various options of this script.

  Multiple options exist to tailor the exclusion rule proposals.
  These config snippets can then be included in the configuration
  in order to tune a modsecurity installation,

  Usage: #{__FILE__} [options]
EOF

  opts.banner.gsub!(/^\t/, "")

        opts.separator ""
        opts.separator "Options:"

  opts.on('-d', '--debug', 'Display debugging infos') do |none|
    params[:debug] = true;
  end

  opts.on('-v', '--verbose', 'Be verbose') do |none|
    params[:verbose] = true;
  end

  opts.on('-h', '--help', 'Displays Help') do
    puts opts
    exit
  end

  # START Mode Definition

  # Define startup time / runtime
  opts.on('-s', '--startup', 'Create startup time rule exclusion') do
	params[:sr] = MODE_STARTTIME
  end
  opts.on('-r', '--runtime', 'Create runtime rule exclusion') do
	params[:sr] = MODE_RUNTIME
  end

  # Define if a rule or a target of a rule will be excluded
  opts.on('-R', '--rule', 'Create rule exclusion for a complete rule') do
	params[:rt] = RTMODE_RULE
  end
  opts.on('-T', '--target', 'Create rule exclusion for an individual target of a rule') do
	params[:rt] = RTMODE_TARGET
  end
  
  # Define rule section by-id, by-tag or by-msg
  opts.on('-i', '--byid', "Select rule via rule id") do
    params[:ruleselector] = BY_ID
  end
  opts.on('-t', '--bytag', "Select rule via tag") do
    params[:ruleselector] = BY_TAG
  end
  opts.on('-m', '--bymsg', "Select rule via message") do
    params[:ruleselector] = BY_MSG
  end

  # END Mode Definition

  # Usage notes (to be printed in help text after cli options) 
  notes = <<EOF

  Notes:

  The order of the exclusion rules matter a lot within a ModSecurity
  configuration. Startup time exxclusion rules need to be defined
  after the rule triggering the false positives is being defined
  (In case of the Core Rule Set, this means _after_ the CRS include).
  Runtime rule exclusions on the other hand need to be configured
  _before_ the CRS include.

  There is a cheatsheet explaining the various options
  (startup time / runtime, rule / target, by id / by tag, by message)
  The cheatsheet can be downloaded from the netnea.com website. It
  is linked from within the ModSecurity tutorials.
  
  This script is (c) 2010-2017 by Christian Folini, netnea.com
  It has been released under the GPLv3 license.
  Contact: mailto:christian.folini@netnea.com
  
EOF

  notes.gsub!(/^\t/, "")
  
  opts.on_tail(notes)
end

parser.parse!

ARGV.each do|f|  
  params[:filenames] << f
end

# Mandatory Argument Check
# if params[:man].nil?
#       $stderr.puts "Argument missing in call. This is fatal. Aborting."
#       exit 1
# end

rescue OptionParser::InvalidOption => detail
  puts_error("Invalid Option in command line parameter extraction. This is fatal. Aborting.", detail)
  exit 1
rescue => detail
  puts_error("Unknown error in command line parameter extraction. This is fatal. Aborting.", detail)
  exit 1

end

	vprint("Starting parameter checking", params)

	exit 1 if (check_parameters(params))

	puts dump_parameters(params) if params[:verbose]

	vprint("Starting main program", params)

	events = import_files(params[:filenames], params)

	puts display_report(events, params)

	vprint("Finishing main program. Bailing out.", params)
end

if __FILE__==$0
	main(params)
end

