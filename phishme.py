#!/usr/bin/env python3
#from bs4 import BeautifulSoup
from os import getuid, chown
from pwd import getpwuid
from time import gmtime
from json import dumps
from collections import OrderedDict
import mailbox
import argparse
import email
import re


class Phish:

    # Commonly used regex
    # Splits lines to be used only when a set maximum number of lines is needed or to remove linebreaks.
    LINESPLIT = re.compile("(\r?\n)", re.MULTILINE)
    # Splits email header fields into two capture groups: header name and value
    HEADERSPLIT = re.compile("(^[^:]+):\s+((?:.+\r?\n)+?)(?!\s)", re.MULTILINE)
    # Parse the sections of the email out
    SECTIONSPLIT = re.compile("""((?:-+BEGIN[A-Z -]+.+?\n-+END[A-Z -]+)|[^-\r\n]+)""", re.MULTILINE & re.DOTALL)

    # Common headers that should only appear once in an email header
    SINGLEHEADERS = frozenset(("from", "subject", "to", "date", "return-path", "message-id", "content-type", "sender",
                               "mime-version"))

    # Initialize the class with the default data.
    def __init__(self, body):
        assert isinstance(body, str)
        self.body = body
        self.data = None

    # REPORTER AGENT
    # fields: ip_address, host, os, reporter, reporter_version, email_client
    def __parse_reporter__(self, section):
        self.data["agent"] = {}
        agent = self.data["agent"]
        for pair in Phish.HEADERSPLIT.finditer(section):
            key = pair.group(1).strip().lower()
            val = pair.group(2).strip()
            if key is "reporter agent":
                values = val.split("|")
                if len(values) == 4:
                    agent["reporter"] = values[0]
                    agent["reporter_version"] = values[1]
                    agent["os"] = values[2]
                    agent["email_client"] = values[3]
                else:
                    self.__error__("Incorrect Reporter Agent size of: " + str(len(values)))
            elif key is "ip address":
                agent["ip_address"] = val
            elif key is "computer name":
                agent["host"] = val.lower()
            else:
                self.__error__("Unknown field (" + key + ") in Reporter Agent")

    # EMAIL HEADERS
    # fields: {}
    def __parse_headers__(self, section):
        self.data["headers"] = OrderedDict()
        headers = self.data["headers"]
        for pair in Phish.HEADERSPLIT.finditer(section):
            key = pair.group(1).strip().lower()
            #TODO: double check that sub works this way
            val = Phish.LINESPLIT.sub(pair.group(2).strip())
            if key in Phish.SINGLEHEADERS:
                if key not in headers:
                    headers[key] = val
                else:
                    self.__error__("duplicate header: " + key)
            else:
                if key in headers:
                    headers[key].append(val)
                else:
                    headers[key] = [val]

    # REPORT COUNT
    # fields: phishme, suspicious
    def __parse_report_count__(self, section):
        self.data["counts"] = {}
        counts = self.data["counts"]
        for pair in Phish.HEADERSPLIT.finditer(section):
            key = pair.group(1).strip().lower()
            if key is "phishme emails reported":
                counts["phishme"] = int(pair.group(2).strip())
            elif key is "suspicious emails reported":
                counts["suspicious"] = int(pair.group(2).strip())
            else:
                self.__error__("Unknown field (" + key + ") in Report Count")


    # URLS
    # fields: text, url
    # TODO: finish url parsing
    def __parse_urls__(self, section):
        self.data["urls"] = []
        current_url = None
        for pair in Phish.HEADERSPLIT.finditer(section):
            key = pair.group(1).strip().lower()
            val = pair.group(2).strip()
            if key is "url":
                pass
            elif key is "link text":
                pass


    # ATTACHMENTS
    # fields: md5, sha1, sha256, size, name
    def __parse_attachments__(self, section):
        self.data["attachments"] = []
        current_file = None
        for pair in Phish.HEADERSPLIT.finditer(section):
            key = pair.group(1).strip().lower()
            val = pair.group(2).strip()
            if key is "file name":
                current_file = {}
                self.data["attachments"].append(current_file)
                current_file["name"] = val
            elif key is "file size" and current_file is not None:
                current_file["size"] = int(val)
            elif key is "md5 file checksum" and current_file is not None:
                current_file["md5"] = val.lower()
            elif key is "sha1 file checksum" and current_file is not None:
                current_file["sha1"] = val.lower()
            elif key is "sha256 file checksum" and current_file is not None:
                current_file["sha256"] = val.lower()
            else:
                self.__error__("Unknown field (" + key + ") in Attachments")


    # Reported from folder
    # fields: folder
    def __parse_report_from__(self, section):
        folder = Phish.HEADERSPLIT.search(section)
        if folder != None:
            self.data["folder"] = folder.group(2).strip()
        else:
            self.__error__("Unknown error in Folder. Data: " + folder.group(2).strip())

    # Main parse logic
    def __parse__(self):
        self.data = {}
        # Extract all sections and create a list of them
        for section in Phish.SECTIONSPLIT.finditer(self.body):
            if section.startswith("-"):
                first_n_rest = Phish.LINESPLIT.split(section, 1)
                if len(first_n_rest) == 2 and isinstance(first_n_rest, list):
                    if " URLS-" in first_n_rest[0]:
                        self.__parse_urls__(first_n_rest[1])
                    elif " REPORT COUNT" in first_n_rest[0]:
                        self.__parse_report_count__(first_n_rest[1])
                    elif " EMAIL HEADERS-" in first_n_rest[0]:
                        self.__parse_headers__(first_n_rest[1])
                    elif " REPORTER AGENT-" in first_n_rest[0]:
                        self.__parse_reporter__(first_n_rest[1])
                    elif " ATTACHMENTS-" in first_n_rest[0]:
                        self.__parse_attachments__(first_n_rest[1])
            elif section.startswith("Reported"):
                self.__parse_report_from__(section)

    # Store parse errors into an errors array
    def __error__(self, val):
        assert isinstance(val, str)
        if "errors" not in self.data or self.data["errors"] is None:
            self.data["errors"] = []
        self.data["errors"].append(val)

    def __str__(self):
        if self.data is None:
            self.__parse__()
            self.body = None
        return dumps(self.data)

# Parse arguments from command line
# args: log folder path, alt mbox name
# TODO finish arg parse
def arg_parse():
    arg = argparse()
    pass


# returns the mailbox path of the current user
mail_user = getpwuid(getuid())[0]
mail_dir = "/var/mail/"

key_list = []

# Open and lock the mailbox
mbox = mailbox.mbox(mail_dir + mail_user)
mbox.lock()

# TODO: add argument inputs log dir needs to be a directory that a file name can be appended to.
log_dir = ""

log_name = str(gmtime()) + ".log"
# TODO check to make sure mbox has items before creating file
with open(log_dir + log_name, mode="w") as log_file:
    for key, message in mbox.iteritems():
        assert isinstance(message, email.message)
        key_list.append(key)
        try:
            payload = message.get_payload()
            text_body = None
            for doc in payload:
                # We are looking for the email body in text format. We can add the ability to look for text/html version
                # if we need to later on and use bs4 with get_text
                # TODO: Don't think inline is required. Should make sure it isn't attachment though. maybe another check
                if 'inline' in doc.get('Content-Disposition') and doc.get_content_type() == 'text/plain':
                    text_body = doc.get_payload()
                    break
            # create a phish object from the text body. If it was not found raise a error and output it.
            if text_body is not None:
                phish_file = Phish(text_body)
            else:
                # TODO: maybe change this as it was not intended to mean this or add data to represent this better.
                raise FileNotFoundError()
            # Write the data out to the log file
            log_file.write(phish_file)
        # TODO: throw error output to log if it does not parse correctly.
        except FileNotFoundError:
            pass

try:
    for key in key_list:
        mbox.remove(key)
finally:
    mbox.flush()
    mbox.unlock()
    mbox.close()
    # TODO: does a uid gid chown need to be done?
