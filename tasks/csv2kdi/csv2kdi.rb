# frozen_string_literal: true

require_relative "lib/csv2kdi_helper"

module Kenna
  module Toolkit
    class Csv2kdi < Kenna::Toolkit::BaseTask
      include Kenna::Toolkit::Csv2kdihelper

      def self.metadata
        {
          id: "csv2kdi",
          name: "csv2kdi",
          description: "Converts CSV source to KDI JSON",
          options: [
            { name: "csv_in",
              type: "string",
              required: false,
              default: "input.csv",
              description: "CSV to be converted to KDI JSON" },
            { name: "has_header",
              type: "boolean",
              required: false,
              default: true,
              description: "Does the input file have a header?" },
            { name: "meta_file",
              type: "string",
              required: false,
              default: "meta.csv",
              description: "File to map input to Kenna fields" },
            { name: "skip_autoclose",
              type: "string",
              required: false,
              default: "false",
              description: "If vuln not in scan, do you want to close vulns?" },
            { name: "appsec_findings",
              type: "string",
              required: false,
              default: "false",
              description: "Field to populate findings appsec model" },
            { name: "assets_only",
              type: "string",
              required: false,
              default: "false",
              description: "Field to indicate assets only - no vulns" },
            { name: "domain_suffix",
              type: "string",
              required: false,
              default: nil,
              description: "Optional domain suffix for hostnames" },
            { name: "input_directory",
              type: "string",
              required: false,
              default: "input",
              description: "Where input files are found. Path is relative to #{$basedir}/" },
            { name: "output_directory",
              type: "string",
              required: false,
              default: "output",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}/" },
            { name: "kenna_api_host",
              type: "string",
              required: false,
              default: "api.kennasecurity.com",
              description: "Host used for the API endpoint" },
            { name: "kenna_connector_id",
              type: "integer",
              required: false,
              default: nil,
              description: "ID required for connector to ingest file converted" },
            { name: "kenna_api_key",
              type: "string",
              required: false,
              default: nil,
              description: "Kenna API code to be used to ingest" }
          ]
        }
      end

      def run(opts)
        super # opts -> @options

        @csv_in = @options[:csv_in]
        @has_header = @options[:has_header]
        @meta_file = @options[:meta_file]
        $skip_autoclose = @options[:auto_close]
        @appsec_findings = @options[:appsec_findings]
        @assets_only = @options[:assets_only]
        @domain_suffix = @options[:domain_suffix]
        @kenna_api_host = @options[:kenna_api_host]
        @kenna_connector_id = @options[:kenna_connector_id]
        @kenna_api_key = @options[:kenna_api_key]
        @output_directory = @options[:output_directory]
        @input_directory = @options[:input_directory]
        @domain_suffix = @options[:domain_suffix]

        @debug = true
        $map_locator = ""

        # Global variables required between methods
        $assets = []
        $vuln_defs = []
        $mapping_array = []
        $date_format_in = ""

        CSV.parse(File.open("#{$basedir}/#{@input_directory}/#{@meta_file}", "r:iso-8859-1:utf-8", &:read), headers: @has_header.eql?("true") ? true : false) do |row|
          $mapping_array << Array[row[0], row[1]]
          $mapping_array.compact
        end
        # headers =
        $date_format_in = $mapping_array.assoc("date_format").last.to_s
        $map_locator = $mapping_array.assoc("locator").last.to_s
        map_file = $mapping_array.assoc("file").last.to_s
        map_ip_address = $mapping_array.assoc("ip_address").last.to_s
        map_mac_address = $mapping_array.assoc("mac_address").last.to_s
        map_hostname = $mapping_array.assoc("hostname").last.to_s
        map_ec2 = $mapping_array.assoc("ec2").last.to_s
        map_netbios = $mapping_array.assoc("netbios").last.to_s
        map_url = $mapping_array.assoc("url").last.to_s
        map_fqdn = $mapping_array.assoc("fqdn").last.to_s
        map_external_id = $mapping_array.assoc("external_id").last.to_s
        map_database = $mapping_array.assoc("database").last.to_s
        map_application = $mapping_array.assoc("application").last.to_s
        map_tags = $mapping_array.assoc("tags").last.to_s
        map_tag_prefix = $mapping_array.assoc("tag_prefix").last.to_s
        map_owner = $mapping_array.assoc("owner").last.to_s
        map_os = $mapping_array.assoc("os").last.to_s
        map_os_version = $mapping_array.assoc("os_version").last.to_s
        map_priority = $mapping_array.assoc("priority").last.to_s

        if @assets_only == "false" # Added for ASSET ONLY Run
          map_scanner_source = $mapping_array.assoc("scanner_source").last.to_s
          map_scanner_type = $mapping_array.assoc("scanner_type").last.to_s
          map_scanner_id = $mapping_array.assoc("scanner_id").last.to_s
          map_scanner_id.encode!("utf-8")

          map_additional_fields = $mapping_array.assoc("additional_fields").last.to_s
          map_details = $mapping_array.assoc("details").last.to_s

          map_created = $mapping_array.assoc("created").last.to_s
          map_scanner_score = $mapping_array.assoc("scanner_score").last.to_s
          map_last_fixed = $mapping_array.assoc("last_fixed").last.to_s
          map_last_seen = $mapping_array.assoc("last_seen").last.to_s
          map_status = $mapping_array.assoc("status").last.to_s
          map_closed = $mapping_array.assoc("closed").last.to_s
          map_port = $mapping_array.assoc("port").last.to_s
          map_cve_id = $mapping_array.assoc("cve_id").last.to_s
          map_wasc_id = $mapping_array.assoc("wasc_id").last.to_s
          map_cwe_id = $mapping_array.assoc("cwe_id").last.to_s
          map_name = $mapping_array.assoc("name").last.to_s
          map_description = $mapping_array.assoc("description").last.to_s
          map_solution = $mapping_array.assoc("solution").last.to_s
          score_map_string = $mapping_array.assoc("score_map").last.to_s
          status_map_string = $mapping_array.assoc("status_map").last.to_s
          score_map = JSON.parse(score_map_string) unless score_map_string.nil? || score_map_string.empty?
          status_map = JSON.parse(status_map_string) unless status_map_string.nil? || status_map_string.empty?
        end

        # Configure Date format
        ###########################
        # CUSTOMIZE Date format
        ###########################
        # date_format_in = "%m/%d/%Y %H:%M"
        date_format_KDI = "%Y-%m-%d-%H:%M:%S"
        kdi_entry_total = 0
        kdi_subfiles_out = 0
        @uploaded_files = []
        CSV.parse(File.open("#{$basedir}/#{@input_directory}/#{@csv_in}", "r:bom|utf-8", &:read), headers: @has_header) do |row|
          ##################
          #  CSV MAPPINGS  #
          ##################
          # Asset settings #
          ##################
          kdi_entry_total += 1
          file = row[map_file.to_s] # (string) path to affected file
          ip_address = row[map_ip_address.to_s] # (string) ip_address of internal facing asset
          mac_address = row[map_mac_address.to_s] # (mac format-regex) MAC address asset
          hostname = row[map_hostname.to_s] # (string) hostname name/domain name of affected asset
          ec2 = row[map_ec2.to_s] # (string) Amazon EC2 instance id or name
          netbios = row[map_netbios.to_s] # (string) netbios name
          url = row[map_url.to_s]
          url = url.strip unless url.nil? # (string) URL pointing to asset
          fqdn = row[map_fqdn.to_s] # (string) fqdn of asset
          external_id = row[map_external_id.to_s] # (string) ExtID of asset-Often used as an int org name for asset
          database = row[map_database.to_s] # (string) Name of database
          application = row[map_application.to_s] # (string) ID/app Name

          # Added for ASSET ONLY Run
          hostname += ".#{@domain_suffix}" if !@domain_suffix.nil? && (@assets_only == "false" || @assets_only == false)

          #########################
          # Asset Metadata fields #
          #########################
          tag_list = map_tags.split(",") # (string) list of strings that correspond to tags on an asset
          prefix_list = map_tag_prefix.split(",")
          tags = []
          count = 0
          tag_list.each do |col|
            col = col.gsub(/\A['"]+|['"]+\Z/, "")
            if !row[col].nil? && !row[col].empty?
              tags << if prefix_list.empty?
                        (row[col]).to_s
                      else
                        prefix_list[count] + (row[col]).to_s
                      end
            end
            count += 1
          end
          owner = row[map_owner.to_s] # (string) Some string that identifies an owner of an asset
          os = row[map_os.to_s] # (string) Operating system of asset
          os_version = row[map_os_version.to_s] # (string) OS version
          priority = row[map_priority.to_s].to_i unless row[map_priority.to_s].nil? || row[map_priority.to_s].empty?
          # (Integer) Def:10 - Priority of asset (int 1 to 10).Adjusts asset score.

          if @assets_only == "false"

            #########################
            # Vulnerability Section #
            #########################
            scanner_type = if map_scanner_source == "static"
                             map_scanner_type.to_s # (string) - default is freeform if nil from CSV
                           else
                             row[map_scanner_type.to_s] # (string) - default is freeform if nil from CSV
                           end
            raise "no scanner type found!" unless !scanner_type.nil? && !scanner_type.empty?

            scanner_id = row[map_scanner_id.to_s]
            raise "no scanner id found!" unless !scanner_id.nil? && !scanner_id.empty?

            details = row[map_details.to_s] # (string) - Details about vuln
            created = row[map_created.to_s]
            if score_map.nil? || score_map.empty?
              scanner_score = row[map_scanner_score.to_s].to_i unless row[map_scanner_score.to_s].nil? || row[map_scanner_score.to_s].empty?
            else
              scanner_score = score_map[row[map_scanner_score.to_s]].to_i unless row[map_scanner_score.to_s].nil? || row[map_scanner_score.to_s].empty?
            end
            last_fixed = row[map_last_fixed.to_s] # (string) - Last fixed date
            last_seen = row[map_last_seen.to_s]
            status = if status_map.nil? || status_map.empty?
                       row[map_status.to_s] # (string) #Rqd Def if nil; open status by default if not in import
                     else
                       status_map[row[map_status.to_s]]
                     end

            closed = row[map_closed.to_s] # (string) Date it was closed
            port = row[map_port.to_s].to_i unless row[map_port.to_s].nil? || row[map_port.to_s].empty?

            ############################
            # Vulnerability Definition #
            ############################

            # in vuln section ##  scanner =
            # in vuln section ##  scanner_id =
            cve_id = row[map_cve_id.to_s] # (string) Any CVE(s)?
            wasc_id = row[map_wasc_id.to_s] # (string) Any WASC?
            cwe_id = row[map_cwe_id.to_s] # (string) Any CWE?
            name = row[map_name.to_s] # (string) Name/title of Vuln
            description = row[map_description.to_s] # (string) Description
            solution = row[map_solution.to_s] # (string) Solution
          end

          # #call the methods that will build the json now##
          if status.nil? || status.empty?
            status = if @appsec_findings == "false"
                       "open"
                     else
                       "new"
                     end
          end

          # Convert the dates
          created = Time.strptime(created, $date_format_in).strftime(date_format_KDI) unless created.nil? || created.empty?
          last_fixed = Time.strptime(last_fixed, $date_format_in).strftime(date_format_KDI) unless last_fixed.nil? || last_fixed.empty?

          last_seen = if last_seen.nil? || last_seen.empty?
                        # last_seen = "2019-03-01-14:00:00"
                        Time.now.strftime(date_format_KDI)
                      else
                        Time.strptime(last_seen, $date_format_in).strftime(date_format_KDI)
                      end

          closed = Time.strptime(closed, $date_format_in).strftime(date_format_KDI) unless closed.nil?

          if @appsec_findings == "true"
            additional_fields_list = map_additional_fields.split(",") unless map_additional_fields.nil?
            additional_fields = nil
            if !additional_fields_list.nil? && !additional_fields_list.empty?
              additional_fields_list.each do |col|
                col = col.gsub(/\A['"]+|['"]+\Z/, "")
                if !row[col].nil? && !row[col].empty?
                  if additional_fields.nil?
                    additional_fields = { col => row[col] }
                  else
                    additional_fields.merge!({ col => row[col] })
                  end
                end
              end
            end
            additional_fields.compact if !additional_fields.nil? && !additional_fields.empty?
          end

          ### CREATE THE ASSET
          done = create_asset(file, ip_address, mac_address, hostname, ec2, netbios, url, fqdn, external_id, database, application, tags, owner, os, os_version, priority)
          # puts "create assset = #{done}"
          next unless done

          ### ASSOCIATE THE ASSET TO THE VULN

          if @assets_only == "false" # Added for ASSET ONLY Run
            if @appsec_findings == "false"
              create_asset_vuln(hostname, ip_address, file, mac_address, netbios, url, ec2, fqdn, external_id, database, scanner_type, scanner_id, details, created, scanner_score, last_fixed,
                                last_seen, status, closed, port)
            else
              ### ASSOCIATE THE ASSET TO THE findings/vuln
              create_asset_findings(file, url, external_id, scanner_type, scanner_id, additional_fields, created, scanner_score,
                                    last_seen, status, closed)
            end
            # CREATE A VULN DEF THAT HAS THE SAME ID AS OUR VULN/finding
            create_vuln_def(scanner_type, scanner_id, cve_id, wasc_id, cwe_id, name, description, solution)
          end

          if kdi_entry_total > 9999
            kdi_output = generate_kdi_file
            output_dir = "#{$basedir}/#{@options[:output_directory]}"
            filename = "kdiout#{@kenna_connector_id}_#{kdi_subfiles_out += 1}_#{Time.now.strftime('%Y%m%d%H%M%S')}.json"
            write_file output_dir, filename, JSON.pretty_generate(kdi_output)
            print_good "Output ##{kdi_subfiles_out} is available at: #{output_dir}/#{filename}"

            ### Uploading & staging to be run if we're all configured
            if @kenna_connector_id && @kenna_api_host && @kenna_api_key
              # print_good "Attempting to upload to Kenna API at #{@kenna_api_host}"
              response_json = upload_file_to_kenna_connector @kenna_connector_id, @kenna_api_host, @kenna_api_key, "#{output_dir}/#{filename}"

              filenum = response_json.fetch("data_file")
              @uploaded_files << filenum
              end
            kdi_entry_total = 0
            $assets = []
            $vuln_defs = []
            print_good "Now I am going to go process some more of your fat CSV input"
          end
        end

        kdi_output = generate_kdi_file
        output_dir = "#{$basedir}/#{@options[:output_directory]}"
        filename = "kdiout#{@kenna_connector_id}_#{kdi_subfiles_out += 1}_#{Time.now.strftime('%Y%m%d%H%M%S')}.json"
        write_file output_dir, filename, JSON.pretty_generate(kdi_output)
        print_good "Output ##{kdi_subfiles_out} is available at: #{output_dir}/#{filename}"

        ### Uploading & running if we're all configured
        return unless @kenna_connector_id && @kenna_api_host && @kenna_api_key

        # print_good "Attempting to upload file to connector_id #{@kenna_connector_id} at Kenna API at #{@kenna_api_host}"
        response_json = upload_file_to_kenna_connector @kenna_connector_id, @kenna_api_host, @kenna_api_key, "#{output_dir}/#{filename}"
        filenum = response_json.fetch("data_file")
        @uploaded_files << filenum
        print_good "Attempting to ingest staged files by running connector_id #{@kenna_connector_id} at Kenna API at #{@kenna_api_host}"
        run_files_on_kenna_connector @kenna_connector_id, @kenna_api_host, @kenna_api_key, @uploaded_files
      end
    end
  end
end
