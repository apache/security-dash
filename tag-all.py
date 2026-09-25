#!/usr/bin/python3
#
# Requirements:
#  wget https://raw.githubusercontent.com/google/gmail-oauth2-tools/master/python/oauth2.py
#
# mjc@apache.org January 2018
#
# References:
#  https://developers.google.com/identity/protocols/OAuth2
#  https://github.com/google/gmail-oauth2-tools/wiki/OAuth2DotPyRunThrough
#  https://yuji.wordpress.com/2011/06/22/python-imaplib-imap-example-with-gmail/
#

# When a new email comes in that is part of an existing thread it
# doesn't contain any tags.  Ideally we want to auto tag it with
# the tags already used on that thread -- it will make it obvious
# which mails need sorting, and for others allow a simple "archive"
# rather than having to remember the thread or search for it.
#
# This might be better as a gmail script so it happens to the inbox
# automatically, or I could run it locally from cron every hour for now

import email
from email.header import decode_header
import imaplib
import re
import csv
from oauth2 import RefreshToken, TestImapAuthentication, GenerateOAuth2String
import os
from pprint import pprint
import time
from optparse import OptionParser
from datetime import datetime, timedelta

from dotenv import load_dotenv
load_dotenv()

############################################################

def connect_to_gmail():
    # Use our refresh token to get a token for this session
    response = RefreshToken(os.getenv('CLIENT_ID'), os.getenv('CLIENT_SECRET'), os.getenv('REFRESH_TOKEN'))
    if ("error" in response):
        print ("Authentication failed: %s" % response["error"])
        return
    imap_conn = imaplib.IMAP4_SSL('imap.gmail.com')
    #imap_conn.debug = 4
    imap_conn.authenticate('XOAUTH2', lambda x: GenerateOAuth2String(os.getenv('OAUTH_USER'), response['access_token'], base64_encode=False))
    return imap_conn

list_response_pattern = re.compile(r'\((?P<flags>.*?)\) "(?P<delimiter>.*)" (?P<name>.*)')

def parse_list_response(line):
    flags, delimiter, mailbox_name = list_response_pattern.match(line).groups()
    mailbox_name = mailbox_name.strip('"')
    return (flags, delimiter, mailbox_name)

def get_all_labels(conn):
    LABELS = []
    resp, data = conn.list('""', '*')
    if resp != 'OK':
        return
    for line in data:
        flags, d, label = parse_list_response(line.decode("utf-8"))
#        if ("\HasNoChildren" in flags):        
        # Ignore gmail special boxes and the inbox and anything labelled to ignore
        if (label == "INBOX" or label.startswith('[Gmail]') or "aaa-ignore" in label or "000-ignore" in label or "/github" in label):
                continue
        LABELS.append(label)
    return LABELS

def parselabels(searchresult):
    try:
        labels = re.search(r'X-GM-LABELS \(([^\)]+)\)', searchresult.decode('utf-8')).groups(1)[0]
        label = csv.reader([labels],delimiter=' ',quotechar='"')
        # filter gmail special labels
        return [i for i in next(label) if (not i.startswith('\\'))]
    except:
        return []

# 'threadlabels' will not have quotes, so we add them:
def label_mail(imap_conn, msgid, subject, threadlabels, dryrun):
    if dryrun:
        print ("Dry run: labeling message with id %s and subject %s with labels %s" % (msgid, subject, threadlabels))
    else:
        # Need to find it again because we switched folders
        oldresult, olddata = imap_conn.uid('search', None, "(X-GM-MSGID "+msgid+")")
        for label in threadlabels:
            print (imap_conn.uid('STORE',olddata[0],"+X-GM-LABELS",'"'+label+'"'))
    
def parseinbox(verbose, dryrun):
    imap_conn = connect_to_gmail()
    if (not imap_conn):
        exit;
    if (verbose):
        print ("Got connection")

    # Select inbox and grab a list of messages
    imap_conn.select("INBOX")
    result, data = imap_conn.uid('search', None, "ALL")
    alluids = ",".join(data[0].decode('utf-8').split(" "))
    if (not alluids):
        return
    result, data = imap_conn.uid('fetch',alluids, '(X-GM-MSGID BODY.PEEK[HEADER.FIELDS (MESSAGE-ID SUBJECT FROM REPLY-TO)] X-GM-THRID X-GM-LABELS)')

    # We want to now look for threads across all mail not just inbox
    imap_conn.select(imap_conn._quote("[Gmail]/All Mail"))
    alllabels = []
    for eachmail in data:
        if len(eachmail) == 2:
            match = re.search('Subject: ([^\r]+)', eachmail[1].decode('utf-8').replace('\r\n ',' '), re.M)
            subject = match.group(1) if match else ""
            if subject.startswith("=?"):
                decoded = decode_header(subject)
                try:
                   subject = decoded[0][0].decode(decoded[0][1])
                except:
                   subject = "???"
            match = re.search('From:[^<]+<([^\r]+)>', eachmail[1].decode('utf-8'))
            mailfrom = match.group(1) if match else ""
            match = re.search('Reply-To:\s+(\S+)', eachmail[1].decode('utf-8'))
            replyto = match.group(1) if match else ""            
            message_id = re.search('Message-ID:\s+(\S+)', eachmail[1].decode('utf-8'), re.IGNORECASE).group(1)
            thread = re.search('X-GM-THRID (\d+)', eachmail[0].decode('utf-8')).group(1)
            msgid = re.search('X-GM-MSGID (\d+)', eachmail[0].decode('utf-8')).group(1)

            if (verbose):
                print ("** Looking at INBOX msgid %s mail subject: %s" %(msgid, subject))
            labels = parselabels(eachmail[0])
            if len(labels) > 0:
                if (verbose):
                    print ("* This mail is already labelled as %s" % labels)
                continue
            if (verbose):
                print ("* This mail has no labels and has threadid %s" %(thread))

            # Let's squirrel away the huntr useless things
            if (mailfrom == "info@huntr.com" and "until report publication" in subject):
                label = "zzz-admin/huntr"
                label_mail(imap_conn,msgid,subject,[label],dryrun)
                continue
                
            # Let's squirrel away the nvd cvmap notifications
            if (replyto == "nvd@nist.gov" and "audit has been completed" in subject):
                label = "zzz-non-issue/aaa-nvd"
                label_mail(imap_conn,msgid,subject,[label],dryrun)
                continue

            # So let's do something clever for github notifications that are not already tagged
            if mailfrom == "notifications@github.com" and not "repository-advisories" in message_id:
                # skip airflow-s notifications so they'll be associated with their
                # respective thread
                match = re.search('\[apache\/([^\]]+)',subject)
                if match:
                    project = match.group(1)
                    print ("Found a new GitHub notification for %s (but I can't do anything about it yet)" %(project))
                    # project = re.sub('-','/', project)
                    label = "zzz-github/" + project
                    label_mail(imap_conn,msgid,subject,[label],dryrun)
                    continue
                
            nresult, ndata = imap_conn.uid('search', None, "(X-GM-THRID "+thread+")")
            alluids = ",".join(ndata[0].decode('utf-8').split(" "))
            if (verbose):
                print ("* With the same threadid are uids %s" %(alluids))
            nresult, ndata = imap_conn.uid('fetch',alluids, '(UID BODY.PEEK[HEADER.FIELDS (DATE SUBJECT)] X-GM-THRID X-GM-LABELS)')
            threadlabels = []
            for neachmail in ndata:
                if len(neachmail) == 2:
                    labels = parselabels(neachmail[0])
                    threadlabels.extend(x for x in labels if x not in threadlabels)
            if len(threadlabels)>0:
                print ("Labels for mail %s with msgid %s should be %s" %(subject,msgid,threadlabels))
                label_mail(imap_conn,msgid,subject,threadlabels,dryrun)
                continue
            if (verbose):
                print ("* No labels found on those messages")

            # Okay, let's specially handle CERT VU# stuff
            for match in re.finditer('(VU#\d+|#YWH-\S+)', subject):
                certvu = match.group(1)
                if (verbose):
                    print ("** Found CERT VU# on subject line %s" %(certvu))
                nresult, ndata = imap_conn.uid('search', None, "(SUBJECT "+certvu+")")
                if (ndata[0]):
                    alluids = ",".join(ndata[0].decode('utf-8').split(" "))
                    if (verbose):
                        print ("* With the same threadid are uids %s" %(alluids))
                    nresult, ndata = imap_conn.uid('fetch',alluids, '(UID BODY.PEEK[HEADER.FIELDS (DATE SUBJECT)] X-GM-THRID X-GM-LABELS)')
                    threadlabels = []
                    for neachmail in ndata:
                        if len(neachmail) == 2:
                            labels = parselabels(neachmail[0])
                            threadlabels.extend(x for x in labels if x not in threadlabels)
                    if len(threadlabels)>0:
                        print ("Labels for mail should be %s" %(threadlabels))
                        label_mail(imap_conn,msgid,subject,threadlabels,dryrun)
                        continue

            # Nothing found, but are there CVE names in the subject?
            cvelabels = []
            if "incomplete fix" not in subject and "bypass" not in subject and "fix is incomplete" not in subject:
                for match in re.finditer('(CVE-\d+-\d+)', subject):
                    ourcve = match.group(1)
                    if (verbose):
                        print ("** Found CVE on subject line %s" %(ourcve))
                    if (len(alllabels) ==0):
                        alllabels = get_all_labels(imap_conn)
                    for label in alllabels:                
                        if ("/"+ourcve in label):
                            cvelabels.append(label)
            if (len(cvelabels)>0):
                if (verbose):
                    print ("** Found threads that match that CVE")
                label_mail(imap_conn,msgid,subject,cvelabels,dryrun)
                continue                                        

                
############################################################

today = time.time()
parser = OptionParser()

parser.add_option("-v", "--verbose", action="store_true", help="be verbose",dest="verbose")
parser.add_option("-d", "--dry-run", action="store_true", help="dry-run, i.e. don't make changes",dest="dryrun")
(options, args) = parser.parse_args()
parseinbox(options.verbose, options.dryrun)
exit()

