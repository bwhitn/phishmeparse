#!/usr/bin/env python3

# phishme.py

# Description:
# Parses a mbox mailbox of PhishMe Emails and records the data in json format in a specified directory.

# TODO: we could attempt to parse html and import BeautifulSoup if a text/plain version doesn't exist.

import argparse
import mailbox
import re
import sys
from calendar import timegm
from collections import OrderedDict
from grp import getgrnam
from json import dumps
# from bs4 import BeautifulSoup
from os import getuid, path, chown
from pwd import getpwuid, getpwnam
from time import gmtime


class Phish:
    # Commonly used regex
    # Splits lines to be used only when a set maximum number of lines is needed or to remove linebreaks.
    LINESPLIT = re.compile("(?:\r?\n)+", re.DOTALL)
    # Splits email header fields into two capture groups: header name and value
    HEADERSPLIT = re.compile("(^[^:]+):\s+((?:.+\r?\n)+?)(?!\s)", re.MULTILINE)
    # Remove the head of the email before the first section
    HEADSPLIT = re.compile("""^(.*?)(-+BEGIN REPORTER AGENT-+.*)""", re.DOTALL)
    # Parse the sections of the email out
    SECTIONSPLIT = re.compile("""(?:(?:(-+BEGIN[A-Z -]+.+?)-+END[A-Z -]+)|^[^-\r\n]+)""", re.MULTILINE + re.DOTALL)

    # Common sets
    # Fields in the short header that is copied on forwarded emails
    HEADFIELDS = frozenset(("from", "to", "subject", "date"))
    # Common headers that should only appear once in an email header
    SINGLEHEADERS = frozenset(("from", "subject", "to", "date", "return-path", "message-id", "content-type", "sender",
                               "mime-version", "content-language", "reply-to"))

    # Initialize the class with the default data.
    def __init__(self, body):
        assert isinstance(body, str)
        self.data = None
        self.body = body
        self.__parse__()

    # REPORTER AGENT
    # fields: ip_address, host, os, reporter, reporter_version, email_client
    def __parse_reporter__(self, section):
        agent = self.data["agent"] = {}
        for pair in Phish.HEADERSPLIT.finditer(section):
            _key = pair.group(1).strip().lower()
            val = pair.group(2).strip()
            if _key == "reporter agent":
                values = val.split("|")
                if len(values) == 4:
                    agent["reporter"] = values[0]
                    agent["reporter_version"] = values[1]
                    agent["os"] = values[2]
                    agent["email_client"] = values[3]
                else:
                    self.__error__("Incorrect Reporter Agent size of: " + str(len(values)))
            elif _key == "ip address":
                agent["ip_address"] = val
            elif _key == "computer name":
                agent["host"] = val.lower()
            else:
                self.__error__("Unknown field (" + _key + ") in Reporter Agent")

    # EMAIL HEADERS
    # fields: {}
    def __parse_headers__(self, section):
        headers = self.data["headers"] = OrderedDict()
        for pair in Phish.HEADERSPLIT.finditer(section):
            _key = pair.group(1).strip().lower()
            val = Phish.LINESPLIT.sub("\\n", pair.group(2).strip())
            if _key in Phish.SINGLEHEADERS:
                if _key not in headers:
                    headers[_key] = val
                else:
                    self.__error__("duplicate header: " + _key)
            else:
                if _key in headers:
                    headers[_key].append(val)
                else:
                    headers[_key] = [val]

    # REPORT COUNT
    # fields: phishme, suspicious
    def __parse_report_count__(self, section):
        counts = self.data["counts"] = {}
        for pair in Phish.HEADERSPLIT.finditer(section):
            _key = pair.group(1).strip().lower()
            if _key == "phishme emails reported":
                counts["phishme"] = int(pair.group(2).strip())
            elif _key == "suspicious emails reported":
                counts["suspicious"] = int(pair.group(2).strip())
            else:
                self.__error__("Unknown field (" + _key + ") in Report Count")

    # URLS
    # fields: text, url
    def __parse_urls__(self, section):
        self.data["urls"] = []
        current_url = None
        for line in section.splitlines():
            pair = line.split(":", 1)
            if len(pair) != 2:
                continue
            _key = pair[0].strip().lower()
            val = pair[1].strip()
            if _key == "url":
                val = val.replace("[.]", ".")
                if current_url is None or "url" in current_url:
                    self.data["urls"].append({_key: val})
                elif "text" in current_url:
                    current_url["url"] = val
                current_url = None
            elif _key == "link text":
                if current_url is None or "url" in current_url:
                    current_url = {"text": val}
                    self.data["urls"].append(current_url)

    # ATTACHMENTS
    # fields: md5, sha1, sha256, size, name
    def __parse_attachments__(self, section):
        self.data["attachments"] = []
        current_file = None
        for pair in Phish.HEADERSPLIT.finditer(section):
            _key = pair.group(1).strip().lower()
            val = pair.group(2).strip()
            if _key == "file name":
                current_file = {}
                self.data["attachments"].append(current_file)
                current_file["name"] = val
            elif _key == "file size" and current_file is not None:
                current_file["size"] = int(val)
            elif _key == "md5 file checksum" and current_file is not None:
                current_file["md5"] = val.lower()
            elif _key == "sha1 file checksum" and current_file is not None:
                current_file["sha1"] = val.lower()
            elif _key == "sha256 file checksum" and current_file is not None:
                current_file["sha256"] = val.lower()
            else:
                self.__error__("Unknown field (" + _key + ") in Attachments")

    # Reported from folder
    # fields: folder
    def __parse_report_from__(self, section):
        folder = section.split(":")
        if folder is not None and len(folder) == 2:
            self.data["folder"] = folder[1].strip()
        else:
            self.__error__("Unknown error in Folder. Data: " + section)

    # Try to parse the head of a forwarded email
    # fields: to, from, date, subject
    def __parse_email_head__(self, section):
        origin = {}
        head_sections = Phish.HEADSPLIT.match(section)
        for line in head_sections.group(1):
            if ":" in line:
                kv = line.split(":", 1)
                _key = kv[0].strip().lower()
                if _key in Phish.HEADFIELDS:
                    origin[_key] = kv[1].strip()
        if len(origin) > 0:
            self.data["origin"] = origin
        return head_sections.group(2)

    # Main parse logic
    def __parse__(self):
        self.data = {}
        # remove the head of the email before
        self.body = self.__parse_email_head__(self.body)
        # Extract all sections and create a list of them
        for section in Phish.SECTIONSPLIT.finditer(self.body):
            section = section.group(0)
            if section.startswith("-"):
                first_n_rest = Phish.LINESPLIT.split(section, 1)
                if len(first_n_rest) == 2 and isinstance(first_n_rest, list):
                    if " URLS-" in first_n_rest[0]:
                        self.__parse_urls__(first_n_rest[1])
                    elif " REPORT COUNT-" in first_n_rest[0]:
                        self.__parse_report_count__(first_n_rest[1])
                    elif " EMAIL HEADERS-" in first_n_rest[0]:
                        self.__parse_headers__(first_n_rest[1])
                    elif " REPORTER AGENT-" in first_n_rest[0]:
                        self.__parse_reporter__(first_n_rest[1])
                    elif " ATTACHMENTS-" in first_n_rest[0]:
                        self.__parse_attachments__(first_n_rest[1])
            elif section.startswith("Reported"):
                self.__parse_report_from__(section)
        # Generic error check to add to parsing errors
        if "agent" not in self.data:
            self.__error__("No Reporter Agent was found")
        if "counts" not in self.data:
            self.__error__("No Report Count was found")
        if "headers" not in self.data:
            self.__error__("No Email Headers were found")
        if "folder" not in self.data:
            self.__error__("No folder information was found")
        self.body = None

    # Store parse errors into an errors array
    def __error__(self, val):
        assert isinstance(val, str)
        if "errors" not in self.data or self.data["errors"] is None:
            self.data["errors"] = []
        self.data["errors"].append(val)

    def __str__(self):
        return dumps(self.data)


# Parse arguments from command line
# args: log folder path, alt user mbox, mailbox path
def arg_parse():
    arg = argparse.ArgumentParser(description="Process PhishMe emails in the users mailbox.")
    arg.add_argument("output_dir", metavar="path", help="The directory that the logs will output to")
    arg.add_argument("-u", metavar="user", default=getpwuid(getuid())[0],
                     help="User mailbox to use (default: %(default)s)")
    arg.add_argument("-p", metavar="path", default="/var/mail/", help="Mailbox path (default: %(default)s)")
    return arg


# Generates JSON string from string message and input email. Used for invalid emails.
def __parse_error__(info, email):
    data = {"errors": [info]}
    subject = email.get('Subject')
    if subject is not None:
        data["headers"] = {'subject': subject}
    return dumps(data)


key_list = []

arg_val = arg_parse().parse_args()

log_name = str(timegm(gmtime())) + ".json"
log_file = None
if path.isdir(arg_val.output_dir):
    log_file = path.join(arg_val.output_dir, log_name)
else:
    print(arg_val.output_dir + " is not a valid directory", file=sys.stderr)
    exit(1)

# Open and lock the mailbox
mbox = mailbox.mbox(arg_val.p + arg_val.u)
mbox.lock()

if len(mbox.keys()) > 0:
    with open(log_file, mode="w") as log_file:
        for key, message in mbox.iteritems():
            key_list.append(key)
            content_type = message.get_content_type()
            phish_file = None
            if content_type is not None and message.is_multipart():
                text_body = None
                payload = message.get_payload()
                for doc in payload:
                    # We are looking for the email body in text format. We can add the ability to look for text/html version
                    # if we need to later on and use bs4 with get_text
                    content_type = doc.get_content_type()
                    if doc.get_content_type() == 'text/plain':
                        text_body = doc.get_payload()
                        break
                # create a phish object from the text body. If it was not found raise a error and output it.
                if text_body is not None:
                    phish_file = str(Phish(text_body))
                else:
                    log_file.write(__parse_error__("No valid email found in multipart email", message))
                # Write the data out to the log file
                log_file.write(phish_file)
            elif content_type is None or content_type == 'text/plain':
                payload = message.get_payload()
                if payload is not None:
                    phish_file = str(Phish(payload))
                    log_file.write(phish_file)
                else:
                    log_file.write(__parse_error__("text/plain found but no valid message body", message))
                    pass
            else:
                log_file.write(__parse_error__("No valid email info in email", message))
            log_file.write("\n")

try:
    for key in key_list:
        mbox.remove(key)
finally:
    mbox.flush()
    mbox.unlock()
    mbox.close()
    chown(arg_val.p + arg_val.u, getpwnam(arg_val.u).pw_uid, getgrnam("root").gr_gid)
