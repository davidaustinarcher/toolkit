# frozen_string_literal: true

require_relative "lib/client"

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
              description: "Filter vulnerabilities using a comma separated list of application tags" },
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
        contrast_auth_header = @options[:contrast_auth_token]         #Do not rename this option, the use of token forces masking in the logs
        contrast_org_id = @options[:contrast_org_id]
        contrast_use_https = @options[:contrast_use_https]
        contrast_application_tags = @options[:contrast_application_tags]
        contrast_environments = @options[:contrast_environments]
        contrast_environments.upcase! unless contrast_environments.nil?
        contrast_severities = @options[:contrast_severities]
        contrast_severities.upcase! unless contrast_severities.nil?
        

        @client = Kenna::Toolkit::Contrast::Client.new(contrast_host, contrast_api_key, contrast_auth_header, contrast_org_id, contrast_use_https)

        kenna_api_host = @options[:kenna_api_host]
        kenna_api_key = @options[:kenna_api_key]
        kenna_connector_id = @options[:kenna_connector_id]

        vulns = @client.get_vulns(contrast_application_tags, contrast_environments, contrast_severities)

        vulns.each do |v|

          asset = {
            "file" => v["application"]["name"],
            "application" => v["application"]["name"],
            "priority" => map_importance_to_priority(v["application"]["importance_description"])            
            #"tags" => ???
          }

          create_kdi_asset(asset)

          vuln_additional_fields = {
            "language" => v["application"]["language"],
            "confidence" => v["confidence"],
            "impact" => v["impact"],
            "likelihood" => v["likelihood"],
            "rule_name": v["rule_name"],
            "rule_title": v["rule_title"]
            #TODO session metadata, environments, servers?
          }
          vuln_additional_fields.compact!

          id = v["uuid"]

          vuln = {
            "scanner_identifier" => id,
            "scanner_type" => SCANNER,
            "scanner_score" => map_severity_to_scanner_score(v["severity"]),
            "created_at" => v["first_time_seen"],
            "last_time_seen" => v["last_seen_at"],
            #"last_fixed_on" => ??
            #"closed_at" => v["closed_time"]
            "status" => map_status_to_open_closed(v["status"]), #(required - valid values open, closed)
            "additional_fields" => JSON.pretty_generate(vuln_additional_fields)
          }
          vuln.compact!

          recommendation = @client.get_trace_recommendation(id)
          story = @client.get_trace_story(id)

          cwe = process_cwe(recommendation["cwe"])

          vuln_def = {
            "scanner_identifier" => id,
            "scanner_type" => SCANNER,
            #"solution" => patches,
            #"cve_identifiers" => cves,
            "cwe_identifiers" => cwe,
            "name" => v["title"],
            "description" => "TODO",
            "solution" => recommendation["recommendation"]["text"]
          }

          vuln_def.compact!

          # Create the KDI entries
          print asset
          print vuln
          print vuln_def
          create_kdi_asset_vuln(asset, vuln)
          create_kdi_vuln_def(vuln_def)
        end

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
      end

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
          "10"
        when "High"
          "8"
        when "Medium"
          "6"
        when "Low"
          "4"
        when "Note"
          "2"
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
        cwe_link.split("/")[-1].gsub(".html", "")
      end 

    end
  end
end
