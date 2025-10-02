# -----------------------------------------------------------------------------------
#              Phishing Email Analysis Tool (with IOC Export)
#
#   This script parses a raw email file (.eml) to extract key security
#   indicators. It then offers to save the extracted IOCs (URLs and hashes)
#   to a file for use with other tools, like an enrichment script.
#
# Author: [PAVLOS THEODOROPOULOS]
# -----------------------------------------------------------------------------------

#  Standard Library imports
import sys
import email
from email import policy
from email.parser import BytesParser
import re
import hashlib
import argparse

# Presentation Class
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def extract_urls(body):
    # Uses a regular expression to find all URLs in a string.
    return re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', body)

def process_attachments(msg):
    # Iterates through email parts, finds attachments, and calculates their hashes
    attachments = []
    for part in msg.walk():
        if part.get_content_disposition() == 'attachment':
            filename = part.get_filename()
            if filename:
                payload = part.get_payload(decode=True)
                if payload:
                    md5_hash = hashlib.md5(payload).hexdigest()
                    sha256_hash = hashlib.sha256(payload).hexdigest()
                    attachments.append({
                        "filename": filename,
                        "md5": md5_hash,
                        "sha256": sha256_hash
                    })
    return attachments

def parse_email(eml_content):
    """
    Main parsing function. extracts headers, URls, and attachments, prints a report,
    and returns the extracted IOCs.
    """
    msg = BytesParser(policy=policy.default).parsebytes(eml_content)

    print(f"{bcolors.HEADER}{bcolors.BOLD}--- Email Headers ---{bcolors.ENDC}")
    print(f"  {bcolors.BOLD}Subject:{bcolors.ENDC} {msg.get('Subject', 'N/A')}")
    print(f"  {bcolors.BOLD}From:{bcolors.ENDC} {msg.get('From', 'N/A')}")
    print(f"  {bcolors.BOLD}To:{bcolors.ENDC} {msg.get('To', 'N/A')}")
    print(f"  {bcolors.BOLD}Date:{bcolors.ENDC} {msg.get('Date', 'N/A')}")
    
    body_text = ""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type in ["text/plain", "text/html"]:
                try:
                    body_text += part.get_payload(decode=True).decode()
                except:
                    body_text += "Could not decode part .\n"
    else:
        try:
            body_text = msg.get_payload(decode=True).decode()
        except:
            body_text = "Could not decode body.\n"
    
    urls = extract_urls(body_text)
    if urls:
        print(f"\n{bcolors.HEADER}{bcolors.BOLD}- URLs Found ({len(urls)})   {bcolors.ENDC}")
        for url in urls:
            print(f"  {bcolors.WARNING}{url}{bcolors.ENDC}")

    attachments = process_attachments(msg)
    if attachments:
        print(f"\n{bcolors.HEADER}{bcolors.BOLD}-Attachments Found ({len(attachments)})  {bcolors.ENDC}")
        for att in attachments:
            print(f"  {bcolors.BOLD}Filename:{bcolors.ENDC} {att['filename']}")
            print(f"  {bcolors.FAIL}MD5:{bcolors.ENDC}      {att['md5']}")
            print(f"  {bcolors.FAIL}SHA256:{bcolors.ENDC}   {att['sha256']}")
    
    return urls, attachments

    # asks the user if they want to save the extracted IOCs to a fiile,
    # and it writes all URLs and SHA256 hashes to iocs.txt
def save_iocs(urls, attachments):
    if not urls and not attachments:
        return

    choice = input(f"\n{bcolors.BOLD}Do you want to save these findings to iocs.txt? (y/n): {bcolors.ENDC}").lower()
    
    if choice == 'y' or choice == 'yes':
        # using a set automatically handles any duplicate IOCs
        iocs_to_save = set()
        
        for url in urls:
            iocs_to_save.add(url)
        for att in attachments:
            iocs_to_save.add(att['sha256'])
            
        try:
            with open('iocs.txt', 'w') as f:
                for ioc in sorted(list(iocs_to_save)):
                    f.write(f"{ioc}\n")
            print(f"{bcolors.OKGREEN}Successfully saved {len(iocs_to_save)} unique IOCs to iocs.txt.{bcolors.ENDC}")
        except Exception as e:
            print(f"{bcolors.FAIL}Error: Could not wrrite to iocs.txt. Details: {e}{bcolors.ENDC}")
    else:
        print("IOCs not saved.")

# Main function to handle arguments, file reading, and orchestrate the workflow.
def main():
    parser = argparse.ArgumentParser(description="Parse a raw email (.eml) file to extract security indicators.")
    parser.add_argument("eml_file", help="The path to the  .eml file to be analyzed.")
    args = parser.parse_args()

    try:
        with open(args.eml_file, 'rb') as f:
            eml_content = f.read()
        
        found_urls, found_attachments = parse_email(eml_content)
        
        save_iocs(found_urls, found_attachments)

    except FileNotFoundError:
        print(f"{bcolors.FAIL}Errror: The file '{args.eml_file}' was not found.{bcolors.ENDC}")
        sys.exit(1)
    except Exception as e:
        print(f"{bcolors.FAIL}An unexpected error occurred: {e}{bcolors.ENDC}")
        sys.exit(1)

if __name__ == "__main__":
    main()