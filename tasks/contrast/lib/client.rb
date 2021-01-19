# frozen_string_literal: true

require 'json'

module Kenna
  module Toolkit
    module Contrast
      class Client
        def initialize(contrast_host, contrast_api_key, contrast_auth_header, contrast_org_id, contrast_use_https)
          protocol = contrast_use_https ? "https://" : "http://"
          @base_url = "#{protocol}#{contrast_host}/Contrast/api/ng/#{contrast_org_id}"
          @headers = { "Authorization": "#{contrast_auth_header}", "API-Key": "#{contrast_api_key}" }
        end

        def get_vulns(tags, environments, severities)
          print "Getting vulnerabilities from the Contrast API"

          more_results = true
          offset = 0
          limit = 25
          out = []

          while more_results
            url = "#{@base_url}/orgtraces/filter?expand=application&offset=#{offset}&limit=#{limit}&applicationTags=#{tags}&environments=#{environments}&severities=#{severities}"

            response = RestClient.get(url, @headers)
            body = JSON.parse response.body

            # do stuff with the data
            out.concat(body["traces"])

            print "Fetched #{out.length} of #{body['count']} records"

            # prepare the next request
            offset += limit

            if response.nil? || response.empty? || offset > body["count"]
              morepages = false
              break
            end
          end

          out
        end

        def get_trace_recommendation(id)
          print "Getting recommendation for trace"
          url = "#{@base_url}/traces/#{id}/recommendation"

          response = RestClient.get(url, @headers)
          JSON.parse response.body
        end

        def get_trace_story(id)
          print "Getting story for trace"
          url = "#{@base_url}/traces/#{id}/story"

          response = RestClient.get(url, @headers)
          JSON.parse response.body
        end
      end
    end
  end
end
