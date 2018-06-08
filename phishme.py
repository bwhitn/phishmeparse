#!/usr/bin/env python3
#from bs4 import BeautifulSoup
from os import getuid
from pwd import getpwuid
from time import gmtime
import mailbox
import argparse
import email
import re
from json import dumps

# returns the mailbox path of the current user
mail_dir = "/var/mail/" + getpwuid(getuid())[0]

key_list = []

# Open and lock the mailbox
mbox = mailbox.mbox(mail_dir)
mbox.lock()

#TODO: add argument inputs log dir needs to be a directory that a file name can be appended to.
log_dir = ""

class Phish:

    def __init__(self, body):
        assert isinstance(body, str)
        self.body = body
        self.data = None
        self.__parse__()

    # REPORTER AGENT
    #fields: ip_address, computer_name, OS, reporter, reporter_version, client
    def __parse_reporter__(self, section):
        pass

    # EMAIL HEADERS
    # fields: {}
    def __parse_headers__(self, section):
        pass

    # REPORT COUNT
    # fields: phishme, suspicious
    def __parse_report_count__(self, section):
        pass

    # URLS
    # fields: text, url
    def __parse_urls__(self, section):
        pass

    # ATTACHMENTS
    # fields: md5, sha1, sha256, size, name
    def __parse_attachments__(self, section):
        pass

    # Reported from folder
    # fields: folder
    def __parse_report_from__(self, section):
        pass

    # Main parse logic
    def __parse__(self):
        # Extract all sections and create a list of them
        section_re = re.compile("""((?:-+BEGIN[A-Z -]+.+?\n-+END[A-Z -]+)|[^-\r\n]+)""")
        section_array = section_re.findall(self.body)
        for section in section_array:
            if section.startswith("-"):
                if " URLS-" in section:
                    pass
                elif " REPORT COUNT-" in section:
                    pass
                elif " EMAIL HEADERS-" in section:
                    pass
                elif " REPORTER AGENT-" in section:
                    pass
                elif " ATTACHMENTS-" in section:
                    pass
            elif section.startswith("Reported"):
                pass

    def __str__(self):
        self.data = {}
        return dumps(self.data)

log_name = str(gmtime()) + ".log"


class PhishParseError(RuntimeError):
    pass


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
                if 'inline' in doc.get('Content-Disposition') and doc.get_content_type() == 'text/plain':
                    text_body = doc.get_payload()
                    break
            # create a phish object from the text body. If it was not found raise a error and output it.
            if text_body is not None:
                phish_file = Phish(text_body)
            else:
                #TODO: maybe change this as it was not intended to mean this or add data to represent this better.
                raise FileNotFoundError()
            # Write the data out to the log file
            log_file.write(phish_file)
        #TODO: throw error output to log if it does not parse correctly.
        except FileNotFoundError:
            pass
        except PhishParseError:
            pass

try:
    for key in key_list:
        mbox.remove(key)
finally:
    mbox.flush()
    mbox.unlock()
    mbox.close()