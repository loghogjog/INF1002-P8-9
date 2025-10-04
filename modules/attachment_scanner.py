#---Tristan Tan---#
import requests
import os
import magic
import filetype
import mimetypes
from dotenv import load_dotenv

load_dotenv() # load variables from .env to os.environ
# max weightage score / flagged as malicious
ANTIVIRUS_SCAN_WEIGHT = 100 
MIME_TYPE_SCAN_WEIGHT = 80  
# general weightage scores
SCAN_CLEAN_WEIGHT = 0
SCAN_SUSPICIOUS_WEIGHT = 40
SCAN_NO_RESULT_WEIGHT = 20
SCAN_MALICIOUS_WEIGHT = 100

def get_file_extension(filename) -> str:
    '''
    This function gets the extensions of the file
    '''
    try:
        # split file name from extension(s)
        file_ext = filename.split('.', 1)[1]
    except Exception as e:
        print(f"Get flie extension error: {e}")
    return file_ext


def mime_type_check(name, ext, data) -> bool:
    '''
    This function performs multiple scans to confirm the actual MIME type matches that of the extension
    
    1. Retrieves actual MIME type by looking at magic bytes from the binary data
    2. Uses filetype library to determine both MIME type and extension from binary data
    3. Compares the MIME type guessed by both magic and filetype library to make sure they match
    4. Compares the extension from the filename with the extension guessed by the filetype library
    
    Provides a robust scan as magic, mimetypes and filetype libraries can cross-check each other to ensure the scan result is correct
    (Due to limitations of magic and mimetypes)
    -> magic -> undetectable filetypes will simply return application/octect-stream
    -> mimetypes -> some return types are not accurate
    Thus return a pass as long as cross-checking filetype scan matches the result of one of the other checks
    - reduces possibility of wrong comparison result 
    '''
    try:
        # using python mimetypes library
        mime_type, _ = mimetypes.guess_type(name, strict=True)
        print(f"mime: {mime_type}")

        # using python Magic library (reads first 2048 bytes of data)
        magic_bytes = magic.from_buffer(data[:2048], mime=True)
        print(f"magic: {magic_bytes}")

        # using filetype library
        kind = filetype.guess(data)

        if kind:
            # first part cross-checks against multiple scans, second part checks the actual extension against the declared extension of the attachmnet
            if (kind.mime == magic_bytes or kind.mime == mime_type) and kind.extension == ext:
                return True
            return False
        else:
            # use text-based scanning - no magic bytes in payload
            try:
                file_data = data.decode('utf-8', errors='ignore').lower()
                print(file_data)
                if "wscript.shell" in file_data or "createobject" in file_data:
                    file_type =  "application/x-vbscript"
                elif "powershell" in file_data:
                    file_type = "application/x-powershell"
                elif "console.log" in file_data or "function(" in file_data:
                    file_type = "application/javascript"
                elif data.startswith("@echo"):
                    file_type = "application/x-bat"
                else:
                    file_type = "text/plain"
            except UnicodeDecodeError as e:
                file_type =  "application/octet-stream"
            print(file_type)
            if file_type == "application/octet-stream": # unknown
                return None
            elif not file_type == "text/plain": # suspicious file type
                return False
            else: # plain text
                return True
                
    except Exception as e:
        print(f"MIME scan error: {e}")
        return None




def antivirus_scan(attachment_data):
    '''
    This function performs an antivirus scan by calling 
    '''
    ### Antivirus API 
    url = os.getenv("ANTIVIRUS_URL")

    api_key = os.getenv("ATTACHMENT_API_KEY")

    headers = {
        "x-api-key": api_key,
        "Content-Type": "application/octet-stream"
    }

    try:
        res = requests.post(url, headers=headers, data=attachment_data, timeout=60)

        if res.status_code == 200:
            result = res.json()

            '''
            JSON response example:
            {
                "status":"clean/infected/no",
                "size": size in bytes,
                "realfiletype": filetype
            }
            '''

            if result["status"]:
                ### add in code to return reasons ( findings ) ###
                match result["status"]:
                    case "clean":
                        antivirus_result = "Pass"
                        antivirus_weight = SCAN_CLEAN_WEIGHT
                    case "infected":
                        antivirus_result = "Fail"
                        antivirus_weight = ANTIVIRUS_SCAN_WEIGHT
                    case "no": # antivirus not sure
                        antivirus_result = "Inconclusive"
                        antivirus_weight = SCAN_SUSPICIOUS_WEIGHT
                    case _:
                        antivirus_result = "Unknown"
                        antivirus_weight = SCAN_NO_RESULT_WEIGHT
            return antivirus_result, antivirus_weight
        else:
            print(f"Error: HTTP {res.status_code}")
            return
    except requests.exceptions.RequestException as e:
        print(f"Error occured: {e}")
        return
    except TimeoutError as e:
        print(f"Antivirus scan timed out, rerunning scan")
        return


def is_attachment_safe(attachment) -> list: 
    '''
    Performs various scans on attachments

    First performs a preliminary analysis by scanning for double extensions and 
    for mismatching MIME types

    Secondary scan, when results from preliminary analysis is not enough to conclude, 
    a secondary scan is performed by parsing the attachment to an antivirus API 
    '''
    try:
        attachment_scan_results = []

        ## Double extensions check
        extension = get_file_extension(attachment['name'])
        if len(extension.split('.')) > 1:
            double_extension_result = "Fail"
            d_ext_weight = SCAN_MALICIOUS_WEIGHT
        else:
            double_extension_result = "Pass"
            d_ext_weight = SCAN_CLEAN_WEIGHT
        attachment_scan_results.append({
                "result":"Double Extension Check " + double_extension_result,
                "weight": d_ext_weight
            })

        ### MIME type scan
        mime_check_result =  mime_type_check(**attachment)
        print(mime_check_result)
        if mime_check_result is not None: # Got results
            print("mime")
            if not mime_check_result:
                mime_result = "Fail"
                mime_weight = MIME_TYPE_SCAN_WEIGHT
            else:
                mime_result = "Pass"
                mime_weight = SCAN_CLEAN_WEIGHT

            attachment_scan_results.append({
                "result":"MIME Type Check " + mime_result,
                "weight":mime_weight
            })
        else: # Unknown results
            attachment_scan_results.append({
                "result":"MIME type Scan Unknown Results",
                "weight":SCAN_NO_RESULT_WEIGHT
            })

        ## Preliminary Analysis
        # Immediately exit if both checks fail - saves resources
        if double_extension_result.lower() == "fail" and not mime_check_result:
            return attachment_scan_results, attachment['name']
        
        ## Antivirus Scan
        antivirus_result, antivirus_weight = antivirus_scan(attachment['data'])
        if (antivirus_result, antivirus_result) and (antivirus_result.lower() == "pass" or antivirus_result.lower() == "fail"): # results exists + not unknown scan results
            attachment_scan_results.append({
                "result":"Antivirus Scan " + antivirus_result,
                "weight":antivirus_weight
            })
        else:
            attachment_scan_results.append({
                "result":"Antivirus Scan Results Unknown",
                "weight":SCAN_NO_RESULT_WEIGHT
            })

        return attachment_scan_results, attachment['name']

    except Exception as e:
        print(f"Is Attachment Safe Scan Error: {e}")
        return


def extract_attachments(msg):
    '''
    Extracts all attachments from eml file
    '''
    attachments_list = []

    if msg.is_multipart():
        for part in msg.walk():
            attachment_name = part.get_filename() # to get declared file extension
            if attachment_name:
                # declared extension
                attachment_ext = get_file_extension(attachment_name)

                attachment_raw_data = part.get_payload(decode=True)
                attachments_list.append({
                    "name": attachment_name,
                    "ext" : attachment_ext,
                    "data" : attachment_raw_data
                })
        return attachments_list
    return None

def attachment_evaluation(attachments):
    '''
    Evaluate Attachment Risk
    Main attachment scan function that calls other functions in this module
    '''
    attachment_result_list = []
    if attachments: # attachments extracted
        # perform analysis
        attachments_scan_results = list(map(is_attachment_safe, attachments)) # list of list of results
        try:
            for attachment in attachments_scan_results: # attachment in attachment list
                if attachment[0]: # each scan result for that attachment
                    total_weight = sum([check['weight'] for check in attachment[0] if "weight" in check])
                    final_weight = min(total_weight, 100) # sets weight limit to 100

                    if final_weight == 100: # override: instantly flagged as malicious 
                        attachment_scan_final_result = "Malicious Attachment"
                        attachment_severity = "Critical"
                    elif final_weight >= 50:
                        attachment_scan_final_result = "Attachment Potentially Unsafe"
                        attachment_severity = "Suspicious"
                    else:
                        attachment_scan_final_result = "Safe Attachment"
                        attachment_severity = "Info"
                    # account for multiple attachments
                    # place the result of each attachment in a dict
                    # place list(attachment_scan_results[1]) in dict too <- attachment name
                    # nest attachments in a list and return the list
                else:
                    print("No scan results") # for backend logging, returns empty list anyway
                
                attachment_scan_reasons = [reason['result'] for reason in attachment[0] if "result" in reason] # reasons list
                attachment_result_list.append([attachment_scan_final_result + " - " + attachment[1], attachment_severity, final_weight, attachment_scan_reasons])
            
            return attachment_result_list
        except KeyError as e:
                print(f"KeyError: {e}")
    else:
        print("No attachments found")
        return