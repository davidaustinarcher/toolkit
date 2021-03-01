# frozen_string_literal: true

require_relative "lib/client"
require "time"

module Kenna
  module Toolkit
    class ContrastTask < Kenna::Toolkit::BaseTask
      SCANNER = "Contrast"

      def self.metadata
        {
          id: "contrast",
          name: "Contrast",
          description: "Extract vulnerability data from the Contrast platform",
          options: [
            { name: "contrast_host",
              type: "hostname",
              required: true,
              default: nil,
              description: "Your Contrast hostname (without protocol), e.g. app.contrastsecurity.com" },
            { name: "contrast_api_key",
              type: "api_key",
              required: true,
              default: nil,
              description: "Your Contrast API Key, as displayed in User Settings" },
            { name: "contrast_auth_token",
              type: "api_key",
              required: true,
              default: nil,
              description: "Your Contrast Authorization Header, which can be copied from User Settings" },
            { name: "contrast_org_id",
              type: "string",
              required: true,
              default: nil,
              description: "Your Contrast Organization ID, as displayed in User Settings" },
            { name: "contrast_use_https",
              type: "boolean",
              required: false,
              default: true,
              description: "Set to false if you would like to force an insecure HTTP connection" },
            { name: "contrast_application_tags",
              type: "string",
              required: false,
              default: "",
              description: "Filter vulnerabilities and libraries using a comma separated list of application tags" },
            { name: "contrast_include_vulns",
              type: "boolean",
              required: false,
              default: true,
              description: "Include vulnerabilities from Contrast Assess" },
            { name: "contrast_environments",
              type: "string",
              required: false,
              default: "",
              description: "Filter vulnerabilities using a comma separated list of environments (DEVELOPMENT, QA or PRODUCTION)" },
            { name: "contrast_severities",
              type: "string",
              required: false,
              default: "",
              description: "Filter vulnerabilities using a comma separated list of severities (e.g. CRITICAL,HIGH)" },
            { name: "contrast_include_libs",
              type: "boolean",
              required: false,
              default: false,
              description: "Include vulnerable libraries from Contrast OSS" },
            { name: "kenna_api_key",
              type: "api_key",
              required: false,
              default: nil,
              description: "Kenna API Key" },
            { name: "kenna_api_host",
              type: "hostname",
              required: false,
              default: "api.kennasecurity.com",
              description: "Kenna API Hostname" },
            { name: "kenna_connector_id",
              type: "integer",
              required: false,
              default: nil,
              description: "If set, we'll try to upload to this connector" },
            { name: "output_directory",
              type: "filename",
              required: false,
              default: "output/contrast",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }
          ]
        }
      end

      def run(opts)
        super # opts -> @options

        contrast_host = @options[:contrast_host]
        contrast_api_key = @options[:contrast_api_key]
        contrast_auth_header = @options[:contrast_auth_token] #Do not rename this option, the use of token forces masking in the logs
        contrast_org_id = @options[:contrast_org_id]
        contrast_use_https = @options[:contrast_use_https]
        contrast_application_tags = @options[:contrast_application_tags]
        contrast_environments = @options[:contrast_environments]
        contrast_environments.upcase! unless contrast_environments.nil?
        contrast_severities = @options[:contrast_severities]
        contrast_severities.upcase! unless contrast_severities.nil?
        contrast_include_libs = @options[:contrast_include_libs]
        contrast_include_vulns = @options[:contrast_include_vulns]
        results = false;

        @client = Kenna::Toolkit::Contrast::Client.new(contrast_host, contrast_api_key, contrast_auth_header, contrast_org_id, contrast_use_https)

        kenna_api_host = @options[:kenna_api_host]
        kenna_api_key = @options[:kenna_api_key]
        kenna_connector_id = @options[:kenna_connector_id]

        if contrast_include_vulns == true
          #Fetch vulnerabilities from the Contrast API
          vulns = @client.get_vulns(contrast_application_tags, contrast_environments, contrast_severities)

          #Loop through the vulnerabilities found
          vulns.each_with_index do |v,i|
            if i % 10 == 0
              print "Processing #{i+1}/#{vulns.count} vulnerabilities"
            end

            asset = create_application(v["application"]["app_id"], v["application"]["name"], v["application"]["importance_description"], v["application"]["language"])

            id = v["uuid"]

            story = @client.get_trace_story(id)

            if story != nil
              details = format_story(story)
            end

            vuln = {
              "scanner_identifier" => id,
              "scanner_type" => SCANNER,
              "scanner_score" => map_severity_to_scanner_score(v["severity"]),
              "created_at" => Time.at(v["first_time_seen"].to_i/1000).iso8601,
              "last_seen_at" => Time.at(v["last_time_seen"].to_i/1000).iso8601,
              "closed_at" => v["closed_time"].nil? ? nil : Time.at(v["closed_time"].to_i/1000).iso8601,
              "status" => map_status_to_open_closed(v["status"]), #(required - valid values open, closed)
              "details" => details
            }
            vuln.compact!

            recommendation = @client.get_trace_recommendation(id, v["rule_name"])

            cwe = process_cwe(recommendation["cwe"])

            vuln_def = {
              "scanner_identifier" => id,
              "scanner_type" => SCANNER,
              "cwe_identifiers" => cwe,
              "name" => v["title"],
              "description" => "#{contrast_use_https ? "https://" : "http://"}#{contrast_host}/static/ng/index.html#/#{contrast_org_id}/vulns/#{id}/overview",
              "solution" => format_solution(recommendation)
            }

            vuln_def.compact!

            # Create the KDI entries
            create_kdi_asset(asset)
            create_kdi_asset_vuln(asset, vuln)
            create_kdi_vuln_def(vuln_def)
            results=true;
          end
        end

        if contrast_include_libs == true
          #Fetch a list of relevant applications
          apps = @client.get_application_ids(contrast_application_tags)

          #Convert to an array of strings
          apps = apps.map { |f| f["app_id"] }

          libs = @client.get_vulnerable_libraries(apps)

          libs.each_with_index do |l,i|
            if i % 10 == 0
              print "Processing #{i+1}/#{l.count} libraries"
            end

            #For each application using this lib
            l["apps"].each do |a|

              #Check that this app is in our apps list (as libs can be used in multiple apps
              if apps.include? a["app_id"]
                asset = create_application(a["app_id"], a["name"], a["importance_description"], a["language"])

                id = l["file_name"]
    
                #To do, figure out the score
                #score = l["vulns"].max_by{|k| k[:severity_value]}
                
                details = "The latest available version of this library is #{l["latest_version"]}"

                vuln = {
                  "scanner_identifier" => id,
                  "scanner_type" => SCANNER,
                  "scanner_score" => 5, #This value is overwritten by Kenna
                  "created_at" => Time.at(a["first_seen"].to_i/1000).iso8601,
                  "last_seen_at" => Time.at(a["last_seen"].to_i/1000).iso8601,
                  "closed_at" => nil,
                  "status" => "open",
                  "details" => details
                }
                vuln.compact!
    
                solution = "This library has #{l["total_vulnerabilities"]} CVE(s), consider upgrading this library to a newer version"
                cves = l["vulns"].map { |v| v["name"] }
    
                vuln_def = {
                  "scanner_identifier" => id,
                  "scanner_type" => SCANNER,
                  "cve_identifiers" => cves.join(","),
                  "name" => "The library #{l["file_name"]} has #{l["total_vulnerabilities"]} CVEs",
                  "description" => "#{contrast_use_https ? "https://" : "http://"}#{contrast_host}/static/ng/index.html#/#{contrast_org_id}/libraries/java/#{l["hash"]}",
                  "solution" => solution
                }

                vuln_def.compact!
    
                # Create the KDI entries
                create_kdi_asset(asset)
                create_kdi_asset_vuln(asset, vuln)
                create_kdi_vuln_def(vuln_def)
                results=true;
              end
            end  
          end
        end


        if results == true
          ### Write KDI format
          kdi_output = { skip_autoclose: false, assets: @assets, vuln_defs: @vuln_defs }
          output_dir = "#{$basedir}/#{@options[:output_directory]}"
          filename = "generator.kdi.json"
          write_file output_dir, filename, JSON.pretty_generate(kdi_output)
          print_good "Output is available at: #{output_dir}/#{filename}"

          ### Finish by uploading if we're all configured
          return unless kenna_connector_id && kenna_api_host && kenna_api_key

          print_good "Attempting to upload to Kenna API at #{kenna_api_host}"
          upload_file_to_kenna_connector kenna_connector_id, kenna_api_host, kenna_api_key, "#{output_dir}/#{filename}"
        else 
          print_good "Extract complete, nothing to upload"
        end
      end

      def create_application(app_id, name, importance, language )
        tags = @client.get_application_tags(app_id).dup
        tags.push(importance) unless importance.nil?
        tags.push(language)

        asset = {
          "file" => name,
          "application" => name,          
          "tags" => tags
        }

        asset
      end 

      ##https://help.kennasecurity.com/hc/en-us/articles/360000862303-Asset-Prioritization-In-Kenna
      def map_importance_to_priority(importance)
        case importance
        when "CRITICAL"
          "10"
        when "HIGH"
          "8"
        when "MEDIUM"
          "6"
        when "LOW"
          "4"
        when "UNIMPORTANT"
          "2"
        end
      end

      def map_severity_to_scanner_score(severity)
        case severity
        when "Critical"
          10
        when "High"
          8
        when "Medium"
          6
        when "Low"
          3
        when "Note"
          1
        end
      end

      def map_status_to_open_closed(status)
        case status
        when "Reported", "Suspicious", "Confirmed"
          "open"
        when "Remediated", "Fixed", "Not a Problem"
          "closed"
        end
      end 

      def process_cwe(cwe_link)
        "CWE-" + cwe_link.split("/")[-1].gsub(".html", "")
      end 

      def format_story(story)
        chapters = story["story"]["chapters"]
        risk = story["story"]["risk"]["text"]

        description = "What happened?"
        chapters.each do |c|
          description += "\n\n" + c["introText"]
          description += "\n" + CGI.escapeHTML(c["body"]) unless c["body"].nil?

          #Collapsed rules will have properties array
          if c["properties"] != nil
            c["properties"].each do |key, value|
              #print "P's #{key} is #{value}"
              description += "\n" + value["name"]
            end
          end
        end
        description += "\n\nWhat's the risk?\n\n"
        description += wrap(risk)

        description
      end

      def format_solution(rec)
        solution = wrap(rec["recommendation"]["text"])
        solution += "\n\nOWASP: " + rec["owasp"] unless rec["owasp"].nil?
      end

      def wrap(s, width=100)
        s.gsub(/(.{1,#{width}})(\s+|\Z)/, "\\1\n")
      end
    end
  end
end
