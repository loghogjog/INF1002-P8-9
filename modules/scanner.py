#---Tristan Tan---#
import requests
import os
import magic
from dotenv import load_dotenv

load_dotenv() # load variables from .env to os.environ
ANTIVIRUS_SCAN_WEIGHT = 100 # critical
MIME_TYPE_SCAN_WEIGHT = 80
SCAN_CLEAN_WEIGHT = 0
SCAN_SUSPICIOUS_WEIGHT = 40
SCAN_NO_RESULT_WEIGHT = 20
SCAN_MALICIOUS_WEIGHT = 100

def get_file_extension(filename):
    '''
    This function gets all extensions of the file
    '''
    try:
        # split file name from extension(s)
        file_ext = filename.split('.', 1)[1]
    except Exception as e:
        print(f"Get flie extension error: {e}")
    return file_ext, len(file_ext.split('.'))


def mime_type_check(attachment_data, declared_file_ext):
    '''Getting actual MIME type'''
    try:
        # magic bytes
        magic_bytes = magic.from_buffer(attachment_data, mime=True)[:2048].split('/')[-1].lower() # getting extension from mimetype e.g. application/pdf 

        return magic_bytes == declared_file_ext
    except Exception as e:
        print(f"Error: {e}")


def is_attachment_safe(attachment): # takes attachment json; specify return type for efficiency -> (type)
    try:
        attachment_scan_results = []
    
    ## Double extensions check
    
        if get_file_extension(attachment['name'])[1] > 1:
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
        if not mime_type_check(attachment['data'], attachment['ext']): #failed MIME type check
            mime_result = "Fail"
            mime_weight = MIME_TYPE_SCAN_WEIGHT
        else:
            mime_result = "Pass"
            mime_weight = SCAN_CLEAN_WEIGHT

        attachment_scan_results.append({
            "rule":"MIME type check" + mime_result,
            "weight":mime_weight
        })

        ### Antivirus API 
        url = "https://eu.developer.attachmentav.com/v1/scan/sync/binary"

        api_key = os.getenv("API_KEY")

        headers = {
            "x-api-key": api_key,
            "Content-Type": "application/octet-stream"
        }

        try:
            res = requests.post(url, headers=headers, data=attachment['data'], timeout=60)

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
                    print(result["status"])
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
                    attachment_scan_results.append({
                        "result":"Antivirus scan " + antivirus_result,
                        "weight":antivirus_weight
                    })
                print(attachment_scan_results)
                return attachment_scan_results
            else:
                print(f"Error: HTTP {res.status_code}")
                return
        except requests.exceptions.RequestException as e:
            print(f"Error occured: {e}")
    except Exception as e:
        print(f"Double Extension error: {e}")


def extract_attachments(msg):
    attachments_list = []

    if msg.is_multipart():
        for part in msg.walk():
            attachment_name = part.get_filename() # to get declared file extension
            if attachment_name:
                # declared extension
                attachment_ext = get_file_extension(attachment_name)[0]

                attachment_raw_data = part.get_payload(decode=True)
                attachments_list.append({
                    "name": attachment_name,
                    "ext" : attachment_ext,
                    "data" : attachment_raw_data
                })
        return attachments_list
    return None

                