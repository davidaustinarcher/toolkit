# Running Contrast Security Task 

This tasks extracts application vulnerability data from the Contrast API and uploads the file to Kenna.

The follow values need to be provided as a minimum to run this task

1. Your Contrast hostname (without protocol), e.g. app.contrastsecurity.com. This can be seen in the address bar when you access the Contrast platform.
1. Your Contrast API Key, as displayed in User Settings.
1. Your Contrast Authorization Header, which can be copied from User Settings.
1. Your Contrast Organization ID, as displayed in User Settings. This should be a GUID.

The data extraction will be limited to applications which are licensed within the Contrast environment.

## Command Line

See the main Toolkit for instructions on running tasks. For this task, if you leave off the Kenna API Key and Kenna Connector ID, the task will create a json file in the default or specified output directory. You can review the file before attempting to upload to the Kenna directly.

### Recommended Steps: 

1. Run with Contrast credentials only to ensure you are able to get data properly
1. Review output for expected data
1. Create Kenna Data Importer connector in Kenna (example name: Contrast KDI) 
1. Manually run the connector with the json from step 1 
1. Click on the name of the connector to get the connector id
1. Run the task with Contrast credentials and Kenna Key/connector id

### Example call: 

```bash 
    docker run -it --rm toolkit:latest \
    task=contrast \
    contrast_host=<your host> \
    contrast_org_id=<your org> \
    contrast_api_key=<your api key> \
    contrast_auth_token=<your auth header>
```

## Complete list of Options:

| Option | Required | Description | default |
| --- | --- | --- | --- |
| contrast_host | true | Your Contrast hostname (without protocol), e.g. app.contrastsecurity.com | n/a |
| contrast_api_key | true | Your Contrast API Key, as displayed in User Settings | n/a |
| contrast_auth_token | true | Your Contrast Authorization Header, which can be copied from User Settings | n/a |
| contrast_org_id | true | Your Contrast Organization ID, as displayed in User Settings | n/a |
| contrast_use_https | false | Set to false if you would like to force an insecure HTTP connection | true |
| contrast_include_vulns | false | Controls whether Contrast Assess vulnerabilities are sent to Kenna | true |
| contrast_application_tags | false | Filter vulnerabilities or libraries using a comma separated list of application tags |  |
| contrast_environments | false | Filter vulnerabilities using a comma separated list of environments (DEVELOPMENT, QA or PRODUCTION). This applies to vulnerabilities only (not libraries).  |  |
| contrast_severities | false | Filter vulnerabilities using a comma separated list of severities (e.g. CRITICAL,HIGH). This applies to vulnerabilities only (not libraries). |  |
| contrast_include_libs | false | Controls whether Contrast OSS library CVE data is sent to Kenna | false |