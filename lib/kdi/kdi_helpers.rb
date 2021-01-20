# frozen_string_literal: true

module Kenna
  module Toolkit
    module KdiHelpers
      def kdi_initialize
        @assets = []
        @vuln_defs = []
        @paged_assets = []
      end

      def uniq(asset)
        {
          "file": asset["file"],
          "ip_address": asset["ip_address"],
          "mac_address": asset["mac_address"],
          "hostname": asset["hostname"],
          "ec2": asset["ec2"],
          "netbios": asset["netbios"],
          "url": asset["url"],
          "fqdn": asset["fqdn"],
          "external_id": asset["external_id"],
          "database": asset["database"],
          "application": asset["application"]
        }.compact
      end

      # Create an asset if it doesnt already exit
      # A "*" indicates required
      #  {
      #  file: string,  + (At least one of the fields with a + is required for each asset.)
      #  ip_address: string, + (See help center or support for locator order set for your instance)
      #  mac_address: string, +
      #  hostname: string, +
      #  ec2: string, +
      #  netbios: string, +
      #  url: string, +
      #  fqdn: string, +
      #  external_id: string, +
      #  database: string, +
      #  application: string, (This field should be used as a meta data field with url or file)
      #
      #  tags: [ string (Multiple tags should be listed and separated by commas) ],
      #  owner: string,
      #  os: string, (although not required, it is strongly recommended to populate this field when available)
      #  os_version: string,
      #  priority: integer, (defaults to 10, between 0 and 10 but default is recommended unless you
      #                      have a documented risk appetite for assets)
      #  vulns: * (If an asset contains no open vulns, this can be an empty array,
      #            but to avoid vulnerabilities from being closed, use the skip-autoclose flag) ]
      #  }
      #
      def create_kdi_asset(asset_hash, dup_check = true)
        kdi_initialize unless @assets

        # if we already have it, skip ... do this by selecting based on our dedupe field
        # and making sure we don't already have it
        uniq_asset_hash = uniq(asset_hash)
        if dup_check
          return nil if @assets.lazy.select { |a| uniq(a) == uniq_asset_hash }.any?
        end

        # create default values
        asset_hash["priority"] = 10 unless asset_hash["priority"]
        asset_hash["tags"] = [] unless asset_hash["tags"]
        asset_hash["vulns"] = []

        # store it in our temp store
        @assets << asset_hash.compact

        # return it
        asset_hash.compact
      end

      def find_or_create_kdi_asset(asset_hash, match_key = nil)
        uniq_asset_hash = uniq(asset_hash)
        asset_hash_key = asset_hash.fetch(match_key) unless match_key.nil?

        # check to make sure it doesnt exist
        a = if match_key.nil?
              @assets.lazy.find { |asset| uniq(asset) == uniq_asset_hash }
            else
              @assets.lazy.find { |asset| asset[match_key] == asset_hash_key }
            end

        # SAnity check to make sure we are pushing data into the correct asset
        unless a # && asset[:vulns].select{|v| v[:scanner_identifier] == args[:scanner_identifier] }.empty?
          puts "Unable to find asset #{asset_hash}, creating a new one... "
          create_kdi_asset(asset_hash, false)
          a = if match_key.nil?
                @assets.lazy.find { |asset| uniq(asset) == uniq_asset_hash }
              else
                @assets.lazy.find { |asset| asset[match_key] == asset_hash_key }
              end
        end

        a
      end

      # create an instance of a vulnerability in our
      # Args can have the following key value pairs:
      # A "*" indicates required
      # {
      #  scanner_identifier: string, * ( each unique scanner identifier will need a
      #                                  corresponding entry in the vuln-defs section below, this typically should
      #                                  be the external identifier used by your scanner)
      #  scanner_type: string, * (required)
      #  scanner_score: integer (between 0 and 10),
      #  override_score: integer (between 0 and 100),
      #  created_at: string, (iso8601 timestamp - defaults to current date if not provided)
      #  last_seen_at: string, * (iso8601 timestamp)
      #  last_fixed_on: string, (iso8601 timestamp)
      #  closed_at: string, ** (required with closed status - This field used with status may be provided on remediated vulns to indicate they're closed, or vulns that are already present in Kenna but absent from this data load, for any specific asset, will be closed via our autoclose logic)
      #  status: string, * (required - valid values open, closed, false_positive, risk_accepted)
      #  port: integer
      # }
      # optional param of match_key will look for a matching asset by locator value
      #    without this optional param it will match on the entire asset array.
      def create_kdi_asset_vuln(asset_hash, vuln_hash, match_key = nil)
        kdi_initialize unless @assets

        a = find_or_create_kdi_asset(asset_hash, match_key)

        # Default values & type conversions... just make it work
        vuln_hash["status"] = "open" unless vuln_hash["status"]
        vuln_hash["port"] = vuln_hash["port"].to_i if vuln_hash["port"]

        # create dates if they weren't passed to us
        now = Time.now.utc.strftime("%Y-%m-%d")
        vuln_hash["last_seen_at"] = now unless vuln_hash["last_seen_at"]
        vuln_hash["created_at"] = now unless vuln_hash["last_seen_at"]

        # add it in
        a["vulns"] = [] unless a["vulns"]
        a["vulns"] << vuln_hash

        vuln_hash
      end

      def create_kdi_asset_finding(asset_hash, finding_hash, match_key = nil)
        kdi_initialize unless @assets

        a = find_or_create_kdi_asset(asset_hash, match_key)

        # Default values & type conversions... just make it work
        finding_hash["triage_state"] = "new" unless finding_hash["triage_state"]
        finding_hash["last_seen_at"] = Time.now.utc.strftime("%Y-%m-%d") unless finding_hash["last_seen_at"]

        # add it in
        a["findings"] = [] unless a["findings"]
        a["findings"] << finding_hash

        finding_hash
      end

      def create_paged_kdi_asset_vuln(asset_hash, vuln_hash, match_key = nil)
        kdi_initialize unless @paged_assets

        uniq_asset_hash = uniq(asset_hash)
        asset_hash_key = asset_hash.fetch(match_key) unless match_key.nil?

        # check to make sure it doesnt exists
        a = if match_key.nil?
              @paged_assets.lazy.find { |asset| uniq(asset) == uniq_asset_hash }
            else
              @paged_assets.lazy.find { |asset| asset[match_key] == asset_hash_key }
            end

        unless a
          a = if match_key.nil?
                @assets.lazy.find { |asset| uniq(asset) == uniq_asset_hash }
              else
                @assets.lazy.find { |asset| asset[match_key] == asset_hash_key }
              end
          if a
            @paged_assets << a
            @assets.delete(a)
          else
            a = asset_hash
            @paged_assets << a
          end
        end

        vuln_hash["status"] = "open" unless vuln_hash["status"]
        vuln_hash["port"] = vuln_hash["port"].to_i if vuln_hash["port"]
        vuln_hash["last_seen_at"] = Time.now.utc.strftime("%Y-%m-%d") unless vuln_hash["last_seen_at"]

        # add it in
        a["vulns"] = [] unless a["vulns"]
        a["vulns"] << vuln_hash

        true
      end

      def clear_data_arrays
        @paged_assets = []
        @vuln_defs = []
      end

      # Args can have the following key value pairs:
      # A "*" indicates required
      # {
      #   scanner_identifier: * (entry for each scanner identifier that appears in the vulns section,
      #                          this typically should be the external identifier used by your scanner)
      #   scanner_type: string, * (matches entry in vulns section)
      #   cve_identifiers: string, (note that this can be a comma-delimited list format CVE-000-0000)
      #   wasc_identifiers: string, (note that this can be a comma-delimited list - format WASC-00)
      #   cwe_identifiers: string, (note that this can be a comma-delimited list - format CWE-000)
      #   name: string, (title or short name of the vuln, will be auto-generated if not set)
      #   description:  string, (full description of the vuln)
      #   solution: string, (steps or links for remediation teams)
      # }
      def create_kdi_vuln_def(vuln_def)
        kdi_initialize unless @vuln_defs

        return if @vuln_defs.lazy.select { |vd| vd["scanner_identifier"] == vuln_def["scanner_identifier"] }.any?

        @vuln_defs << vuln_def

        true
      end
    end
  end
end
