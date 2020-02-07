#requires installation of
#   python3, SlackClient Extensions, hashlib, requests
import os
import time
from datetime import datetime
import slack
import requests
from requests.auth import HTTPBasicAuth
import _thread
import json
import re


# Disables 'InsecureRequestWarning' warning from urllib3
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


## Control variables, Global Defaults, and Configuration ##
DEBUG = 0
MaxCommandLen = 10
#Bot Configuration
BOT_NAME = "McBOT"
Default_Channel = "#csa_bots"
BOT_ID = 'U5YBN0ZB6'

#ePO Connection Configuration
infection_search_window = 3888000000
webclient = None 

vers_dict = {}
regex = re.compile(r'Builder Number: (\d*)')

# Access EPO credentials and Slackbot Token
# Credential format is: EPO_Username\nEPO_Password\nSlackToken
with open("credentials.txt", 'r') as cred_file:
    CROMWELL_usr = cred_file.readline().strip()
    CROMWELL_pass = cred_file.readline().strip()
    SLACK_BOT_TOKEN = cred_file.readline().strip()

# Dictionary of Microsoft OS Build # : Version Info
# Built using ms_buildvers_scraper.py
with open("winvers.json", "r") as vers_file:
    vers_dict = json.load(vers_file)

with open('mcafee_latest_versions.json', 'r') as mcafee_vers_file:
    mcafee_vers_dict = json.load(mcafee_vers_file)

#logFile Configuration
ErrorFile = ".\OperationLogs\ErrorLog.log"
AuditFile = ".\OperationLogs\AuditLog.log"


AT_BOT = "<@" + BOT_ID + ">"
## End of Configuration, Control Variables, and Global Defaults##

##Begin Bot Operations
slack_client = slack.RTMClient(token=SLACK_BOT_TOKEN)


#Core BOT Functions
#Slack channel parser
@slack_client.run_on(event='message')
def parse_slack_output(**slack_rtm_output):
    if slack_rtm_output and len(slack_rtm_output) > 0:

        data = slack_rtm_output['data']

        global webclient
        webclient = slack_rtm_output['web_client']

        try:
            if AT_BOT in data['text']:
                # return text after the @ mention, whitespace removed
                command, channel = data['text'].split(AT_BOT)[1].strip().lower(), data['channel']
                
                if command == '?' or command == 'help':
                    pass
                else:
                    command = 'namecheck ' + command
                
                try:
                    _thread.start_new_thread(command_dict[command[:MaxCommandLen]], (channel,  command[MaxCommandLen: MaxCommandLen+15]))
                except:
                    response = "Sorry I am not familiar with that command, type help for avilable commands."
                    webclient.chat_postMessage(channel=channel, text=response, as_user=True) 

        except Exception as inst:
            if DEBUG == 1:
                log_ToFile("Exception instance encountered: " + inst, "Error")


#Displays help in requested channel
def display_help(channel, usr_args):
    response = """ Hi, I am """ + BOT_NAME + "!" + """
    I am here to help technicans check a computers McAfee Health Status.
    I accept commands in the \""""+ BOT_NAME + """ [Command]\" format.

    Right now I can only do a few things but they include:
    getupdate - has me run a on demand update check
    help or ? - prints this help page
    <computer-name> - has me run a McAfee ePO health check on the client located on [computer-name] Note: computername must be 15chars or less.
    """
    webclient.chat_postMessage(channel=channel, text=response, as_user=True)


def mac_healthchk(response):                #Evaluates OSX Health check data
    if response.find("On-Access Scan Enabled: true") != -1 and response.find("Definitions Up To Date (AMCore Content): true") != -1:
        final_response = "== Health Check PASSED ==" + response
    else:
        final_response = "== Health Check FAILED ==" + response
    return final_response


def win_healthchk(response):                #Evaluates Windows Health check data
    if response.find("false") == -1 and response.find("Definitions Up To Date (AMCore Content): true") != -1:
        final_response = "== Health Check PASSED ==" + response
    else:
        final_response = "== Health Check FAILED ==" + response
    return final_response


def InfectionHistory(usr_args):
    #perform search on ePO server
    hostname = ''
    url = hostname + '/remote/core.executeQuery?target=EPOEvents&select=(select EPOEvents.DetectedUTC EPOEvents.EventTimeLocal EPOEvents.TargetHostName EPOEvents.ThreatName)&where=(where ( and ( newerThan EPOEvents.DetectedUTC '+ str(infection_search_window) +'   ) ( or ( threatcategory_belongs EPOEvents.ThreatCategory "av"  ) ( threatcategory_belongs EPOEvents.ThreatCategory "av.detect"  ) ( threatcategory_belongs EPOEvents.ThreatCategory "av.detect.heuristics"  ) ( threatcategory_belongs EPOEvents.ThreatCategory "av.detect.heuristics"  )  ) ( eq EPOEvents.AnalyzerHostName "'+ usr_args +'"  )  ) )'
    query_result = requests.get(url, auth=HTTPBasicAuth(CROMWELL_usr,CROMWELL_pass), verify=False)
    
    if DEBUG == 1:
        count = query_result.text.count("E")
        print("\n\nquery result count = " + str(count) + "\n\n")
        print("Query Text = "+query_result.text+"\n\n===\n\n")
    if(query_result.text.count("E") > 2):    
        return True
    else:
        return False


#Launches a McAfee health check for user define computer name
def run_namecheck(channel, usr_args):

    hostnames = [
                    "hostname1",
                    "hostname2"
                ]

    hostname = ''
    not_found = 0
    for i in range(len(hostnames)):
        hostname = hostnames[i]
        #give user search launch notice
        response = f"Querying {hostname} McAfee ePO server..."
        webclient.chat_postMessage(channel=channel, text=response, as_user=True)

        # remove special characters from user input
        system_name = re.sub('[\\)\';=*+!^#% ]', '', usr_args)

        #query epo server for os type
        os_query = f"https://{hostname}.psu.ds.pdx.edu:8443/remote/core.executeQuery?target=EPOLeafNode&select=(select EPOComputerProperties.OSType  )&where=(where(eq EPOLeafNode.NodeName \"{system_name}\"))"
        os_result = requests.get(os_query, auth=HTTPBasicAuth(CROMWELL_usr,CROMWELL_pass), verify=False)

        # if query result returns only 'OK:' then machine was not found
        if os_result.text.strip() == 'OK:':
            not_found += 1
        else:
            break
        
    # Evaluates to true if we search for system name on each epo host
    if not_found == len(hostnames):
        not_found_msg = f"\n I could not find a machine with that name. \nPlease double check the system name."
        webclient.chat_postMessage(channel=channel, text=not_found_msg, as_user=True)
        return

    os_string = os_result.text.replace(' ', '').lower() # modify query result for operating system to facilitate string comparisons

    if 'macos' in os_string:
        mac_query_fields = [
                            'AM_CustomProps.AVCMGRbComplianceStatus',
                            'EPOLeafNode.NodeName',
                            'EPOComputerProperties.OSType',
                            'EPOLeafNode.LastUpdate',
                            'AM_CustomProps.bAPEnabled',
                            'AM_CustomProps.bOASEnabled',
                            'EPOProdPropsView_EPOAGENT.productversion',
                            'EPOProdPropsView_THREATPREVENTION.productversion',
                            'AM_CustomProps.V2DATVersion'
                            ]

        query = f"https://{hostname}.psu.ds.pdx.edu:8443/remote/core.executeQuery?target=EPOLeafNode&select=(select {' '.join(mac_query_fields)})&where=(where(eq EPOLeafNode.NodeName \"{system_name}\"))"
        query_result = requests.get(query, auth=HTTPBasicAuth(CROMWELL_usr,CROMWELL_pass), verify=False)
        response = query_result.text
        response = response.replace("OK:", ":heavy_check_mark: :apple: *MacOS Client McAfee Products Up-To-Date* :heavy_check_mark:")


    elif 'windows' in os_string:
        win_query_fields = [
                            'EPOLeafNode.NodeName',
                            'EPOComputerProperties.OSType',
                            'EPOComputerProperties.OSBuildNum',
                            'EPOLeafNode.LastUpdate',
                            'AM_CustomProps.bAPEnabled',
                            'AM_CustomProps.bOASEnabled',
                            'AM_CustomProps.AVCMGRbComplianceStatus',
                            'EPOProdPropsView_EPOAGENT.productversion',
                            'EPOProdPropsView_ENDPOINTSECURITYPLATFORM.productversion',
                            'EPOProdPropsView_TIECLIENTMETA.productversion',
                            'EPOProdPropsView_THREATPREVENTION.productversion',
                            'EPOProdPropsView_WEBCONTROL.productversion',
                            ]

        query = f"https://{hostname}.psu.ds.pdx.edu:8443/remote/core.executeQuery?target=EPOLeafNode&select=(select {' '.join(win_query_fields)})&where=(where(eq EPOLeafNode.NodeName \"{system_name}\"))"
        query_result = requests.get(query, auth=HTTPBasicAuth(CROMWELL_usr,CROMWELL_pass), verify=False)
        response = query_result.text
        
        # format the response to be a list: [name, ostype, osbuild, ...]
        response_entries = response.replace('\r', '').split('\n')
        response_entries = [res for res in response_entries if len(res) > 0]

        mcafee_up_to_date = True
        # regular expression to catch McAfee related fields
        mcafee_pattern = r'Product Version \((.*)\): ([.\d]*)|(.*) Enabled: (.*)|AMCore Content Compliance Status: (\d)'
        build_no = ''
        for i in range(len(response_entries)):
            # convert microsoft os build number to more familiar version info using external list
            build_match = re.search(r'Build Number: (\d*)', response_entries[i])
            if build_match:
                try:
                    build_no = build_match.groups(0)[0]
                    version_info = vers_dict[build_no]
                    response_entries[i] = response_entries[i].replace("OS Build Number", "OS Version")
                    response_entries[i] = response_entries[i].replace(build_no, version_info)
                except KeyError:
                    pass

            # process McAfee fields
            match = re.search(mcafee_pattern, response_entries[i])
            if match:
                # Capture group 4 is the value of the 'AMCore Content Compliace Status' field
                if match.groups()[4] == '1':
                    response_entries[i] = response_entries[i].replace('1', 'true') # replace 1 by with 'true'
                elif match.groups()[4] == '0':
                    response_entries[i] = response_entries[i].replace('0', 'false') # replace 0 with 'false'

                # Captures entries of the form: Product Version (<product>): <version>
                if match.groups()[0]:
                    if mcafee_vers_dict['windows'][match.groups()[0]] == match.groups()[1]: # check version number from query against list
                        response_entries[i] = re.sub(mcafee_pattern, r'\1 Version: \2', response_entries[i])
                    else:
                        mcafee_up_to_date = False
                        if match.groups()[1]:
                            # Reformat text to be of form <Product> Version: <Version>
                            response_entries[i] = re.sub(mcafee_pattern, r'*\1 Version: \2*', response_entries[i])
                        else:
                            # If we get to this point and there's no version number, we assume the product is not installed
                            response_entries[i] = ''

                # Captures entries of the form: <product> Enabled: <value>
                if match.groups()[2]:
                    if match.groups()[3] == 'false': # if product is not enabled we bold the entry before responding to user
                        response_entries[i] = "*" + response_entries[i] + "*" # * <text> * returns bold text to slack chat

        # We replace the 'OK:' response (returned for any valid epo query) with McAfee product status
        if mcafee_up_to_date:
            response_entries[0] = response_entries[0].replace("OK:", ":heavy_check_mark: :windows: *Windows Client McAfee Products Up-To-Date* :heavy_check_mark:")
        else:
            response_entries[0] = response_entries[0].replace("OK:", ":x: *Outdated Client McAfee Products Shown in Bold* :x:")
        
        # Create response text for slack chat by joining response entries list
        response = '\n'.join(response_entries)

    else:
        query = f'https://{hostname}.psu.ds.pdx.edu:8443/remote/core.executeQuery?target=EPOLeafNode&select=(select AM_CustomProps.AVCMGRbComplianceStatus EPOLeafNode.NodeName EPOComputerProperties.OSType EPOComputerProperties.OSBuildNum EPOLeafNode.LastUpdate AM_CustomProps.bAPEnabled AM_CustomProps.bOASEnabled EPOProdPropsView_EPOAGENT.productversion EPOProdPropsView_ENDPOINTSECURITYPLATFORM.productversion EPOProdPropsView_TIECLIENTMETA.productversion AM_CustomProps.ManifestVersion )&where=(where(eq+EPOLeafNode.NodeName "' + system_name + '"))'
        query_result = requests.get(query, auth=HTTPBasicAuth(CROMWELL_usr,CROMWELL_pass), verify=False)

    #perform Multiple Infection history check
    if(InfectionHistory(usr_args)):
        response += "\n\n== WARNING! ==\n\n This machine has multiple major infections in the last 45days! \n== RE-IMAGE REQUIRED! ==\n"

    #send user final response
    webclient.chat_postMessage(channel=channel, text=response, as_user=True)

#Allows logging of events to error and audit logs
def log_ToFile(message, level):

    if DEBUG == 1:
        print(message)
        print(level)
    logging_type_dict = {
        "error" : ErrorFile,
        "Error" : ErrorFile,
        "Audit" : AuditFile,
        "audit" : AuditFile,
    }

    current_file = open(logging_type_dict[level], 'a')
    current_file.write(level + ": @" + "{:%B %d, %Y, %H:%M:%S}".format(datetime.now()) + " - " + message)
    current_file.close()


#functions command dictionary
command_dict = {
    "?" : display_help,
    "help" : display_help,
    "Help" : display_help,
    "namecheck " : run_namecheck,
    "Namecheck " : run_namecheck,
}


#Main BOT control
if __name__ == "__main__":
    #check / verify McAfee ePO API credentials
    try:
        if CROMWELL_pass == "" or CROMWELL_usr == "":
            raise SystemExit(BOT_NAME + " FAILED to locate ePO API credentials; please provide credentails and try again")

        hostname = ''
        url = hostname + '/remote/core.help'
        query_result = requests.get(url, auth=HTTPBasicAuth(CROMWELL_usr,CROMWELL_pass), verify=False)

        if query_result.text.find("<title> - Error report</title>") != -1:
            if DEBUG == 1:
                print("\n Startup - Credential Check == DEBUG query_result output: \n" + query_result.text)
            raise SystemExit("Connected to ePO API but failed to verify credentials; check credentials and restart")
    except:
        if DEBUG == 1:
            print("\n Startup - Credential Check FAILED")
        raise SystemExit(BOT_NAME + " FAILED to verify ePO API credentials; please check credentials & connection before trying again")
    
    try:
        slack_client.start()
    except RuntimeError as re:
        log_ToFile(re, "Error")
    except ValueError :
        pass