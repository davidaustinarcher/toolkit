# frozen_string_literal: true

require_relative "lib/client"

module Kenna
  module Toolkit
    class ContrastTask < Kenna::Toolkit::BaseTask

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

        vulns = @client.contrast_get_vulns(contrast_application_tags, contrast_environments, contrast_severities)

        # vulns.each do |v|

        #   application = v["application"]["name"]
        #   # file??
        #   # tags??

        #   asset = {

        #     "file" => v["application"]["name"],
        #     "application" => v["application"]["name"],
        #     "tags" => tags

        #   }

        #   # scanner_score = ""
        #   scanner_score = if issue.key?("cvssScore")
        #                     issue.fetch("cvssScore").to_i
        #                   else
        #                     vuln_severity.fetch(issue.fetch("severity"))
        #                   end

        #   source = project.fetch("source") if issue.key?("source")
        #   fixedIn = issue.fetch("fixedIn") if issue.key?("fixedIn")
        #   from = issue.fetch("from") if issue.key?("from")
        #   functions = issue.fetch("functions") if issue.key?("functions")
        #   isPatchable = issue.fetch("isPatchable").to_s if issue.key?("isPatchable")
        #   isUpgradable = issue.fetch("isUpgradable").to_s if issue.key?("isUpgradable")
        #   if issue.key?("references")
        #     language = issue.fetch("language") if issue.key? "language",
        #                                                       references = issue.fetch("references")
        #   end
        #   semver = JSON.pretty_generate(issue.fetch("semver")) if issue.key?("semver")
        #   issue_severity = issue.fetch("severity") if issue.key?("severity")
        #   version =  issue.fetch("version") if issue.key?("version")
        #   description = issue.fetch("description") if issue.key?("description")

        #   additional_fields = {
        #     "source" => source,
        #     "fixedIn" => fixedIn,
        #     "from" => from,
        #     "functions" => functions,
        #     "isPatchable" => isPatchable,
        #     "isUpgradable" => isUpgradable,
        #     "language" => language,
        #     "references" => references,
        #     "semver" => semver,
        #     "severity" => issue_severity,
        #     "version" => version,
        #     "identifiers" => identifiers
        #   }

        #   additional_fields.compact!

        #   # craft the vuln hash
        #   vuln = {
        #     "scanner_identifier" => issue.fetch("id"),
        #     "scanner_type" => "Snyk",
        #     "scanner_score" => scanner_score,
        #     "created_at" => issue_obj.fetch("introducedDate"),
        #     "details" => JSON.pretty_generate(additional_fields)
        #   }

        #   vuln.compact!

        #   patches = issue["patches"].first.to_s unless issue["patches"].nil? || issue["patches"].empty?

        #   cves = nil
        #   cwes = nil
        #   unless identifiers.nil?
        #     cve_array = identifiers["CVE"] unless identifiers["CVE"].nil? || identifiers["CVE"].length.zero?
        #     cwe_array = identifiers["CWE"] unless identifiers["CWE"].nil? || identifiers["CVE"].length.zero?
        #     cve_array.delete_if { |x| x.start_with?("RHBA", "RHSA") } unless cve_array.nil? || cve_array.length.zero?
        #     cves = cve_array.join(",") unless cve_array.nil? || cve_array.length.zero?
        #     cwes = cwe_array.join(",") unless cwe_array.nil? || cwe_array.length.zero?
        #   end

        #   vuln_name = nil
        #   vuln_name = issue.fetch("title") unless issue.fetch("title").nil?

        #   vuln_def = {
        #     "scanner_identifier" => issue.fetch("id"),
        #     "scanner_type" => "Snyk",
        #     "solution" => patches,
        #     "cve_identifiers" => cves,
        #     "cwe_identifiers" => cwes,
        #     "name" => vuln_name,
        #     "description" => description
        #   }

        #   vuln_def.compact!

        #   # Create the KDI entries
        #   create_kdi_asset_vuln(asset, vuln)
        #   create_kdi_vuln_def(vuln_def)
        # end

        # ### Write KDI format
        # kdi_output = { skip_autoclose: false, assets: @assets, vuln_defs: @vuln_defs }
        # output_dir = "#{$basedir}/#{@options[:output_directory]}"
        # filename = "generator.kdi.json"
        # write_file output_dir, filename, JSON.pretty_generate(kdi_output)
        # print_good "Output is available at: #{output_dir}/#{filename}"

        # ### Finish by uploading if we're all configured
        # return unless kenna_connector_id && kenna_api_host && kenna_api_key

        # print_good "Attempting to upload to Kenna API at #{kenna_api_host}"
        # #upload_file_to_kenna_connector kenna_connector_id, kenna_api_host, kenna_api_key, "#{output_dir}/#{filename}"
      end
    end
  end
end
