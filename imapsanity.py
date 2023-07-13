from ast import Import
from email.message import EmailMessage
import sys
import imaplib
import email, email.message, email.policy
import re
import traceback
import pprint
from yaml import load
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

class IMAPSanityFiler:

    def __init__(self):
        with open('mailboxes.yml', 'r') as stream:
            self.config = load(stream, Loader=Loader)['mailboxes']

    def run(self, mailbox='ALL'):
        if 'ALL' == mailbox or mailbox in self.config.keys():
            print('Running IMAPSanityFiler against {0} mailbox(s)'.format(mailbox))
            for key in self.config:
                if 'ALL' == mailbox or key == mailbox:
                    self.filers_config = self.config[key]['filers']
                    self.matches_config = self.config[key]['matches']
                    self.process_mailbox(self.config[key])
        else:
            print('Mailbox {0} Not Found'.format(mailbox))

    def process_mailbox(self, mailbox):
        print('Processing mailbox for {0}'.format(mailbox['email']))
        mbox = self.open_inbox(mailbox)
        counter = 0
        if mbox:
            try:
                self.open_inbox(mailbox)
                mbox.select()
                typ, data = mbox.search(None, 'ALL')
                totalCount = len(data[0].split())
                print('Found {0} emails to process'.format(totalCount))
                emailNum = 0
                for num in data[0].split():
                    emailNum = emailNum + 1

                    try:
                        # Get the message
                        typ, data = mbox.fetch(num, '(BODY.PEEK[])')
                        msg = email.message_from_bytes(data[0][1], policy=email.policy.default)

                        # Get JUST the email address and domain
                        match = re.search(r'([\w\.-]+)(@[\w\.-]+)', msg['From'])
                        if match is not None:
                            emailAddr = match.group(0)
                            emailDomain = match.group(2)
                            subject = self.strip_non_ascii(msg['Subject'])

                            for i in range(len(self.matches_config)):
                                cfgSender = None
                                cfgSubject = None
                                cfgOperator = None
                                if 'sender' in self.matches_config[i]:
                                    cfgSender = self.matches_config[i]['sender']
                                if 'subject' in self.matches_config[i]:
                                    cfgSubject = self.matches_config[i]['subject']
                                if 'operator' in self.matches_config[i]:
                                    cfgOperator = self.matches_config[i]['operator']

                                if cfgSender is not None and self.email_matches(cfgSender, emailAddr):
                                    if self.subject_matches(cfgSubject, cfgOperator, subject):
                                        myFiler = self.filers_config[self.matches_config[i]['filer']]
                                        if myFiler is not None:
                                            print('We found a match [{0}] and need to move it to : {1}'.format(emailAddr, myFiler['folder']))
                                            counter = counter + 1

                                            msgDateTuple = email.utils.parsedate_tz(msg['Date'])
                                            msgDateTm = email.utils.mktime_tz(msgDateTuple)

                                            # Copy the message to the SPAM folder
                                            mbox.append(myFiler['folder'], '', imaplib.Time2Internaldate(msgDateTm), str(msg).encode('utf-8'))

                                            # Remove the message from the INBOX
                                            mbox.store(num, '+FLAGS', '\\Deleted')
                                            counter = counter + 1

                        if emailNum % 100 == 0:
                            mbox.expunge()

                    except:
                        print('Error processing email', sys.exc_info()[0])
                        print(traceback.format_exc())

                # Expunge the INBOX
                mbox.expunge()

                print('Moved {0} of {1} emails to the SPAM folder'.format(counter, totalCount))

            except:
                print('Error processing inbox for {0}: {1}'.format(mailbox['email'], sys.exc_info()[0]))
                print(traceback.format_exc())
            finally:
                self.close_inbox(mbox)

    def email_matches(self, configEmail, actualEmail):
        if configEmail.startswith('@'):
            if actualEmail.endswith(configEmail):
                return True
        if configEmail == actualEmail:
            return True
        return False

    def subject_matches(self, configSubject, configOperator, actualSubject):
        if configSubject is None or configSubject == '':
            return True
        if actualSubject is None or actualSubject == '':
            return False
        if configOperator is None or configOperator == 'equals' and configSubject == actualSubject:
            return True
        if configOperator == 'starts' and actualSubject.startswith(configSubject):
            return True
        if configOperator == 'ends' and actualSubject.endswith(configSubject):
            return True
        if configOperator == 'contains' and configSubject in actualSubject:
            return True
        return False

    def open_inbox(self, mailbox):
        mbox = imaplib.IMAP4(mailbox['imap-host'])
        try:
            mbox.login(mailbox['email'], mailbox['password'])
            return mbox
        except imaplib.IMAP4.error as e:
            print('Error opening mbox: ', e)
        return None

    def close_inbox(self, mbox):
        print('Closing mbox')
        try:
            mbox.close()
            mbox.logout()
        except imaplib.IMAP4.error as e:
            print('Error closing inbox: ', e)
        return None

    def strip_non_ascii(self, str):
        ''' Returns the string without non ASCII characters '''
        stripped = (c for c in str if 0 < ord(c) < 127)
        return ''.join(stripped)

def main() -> int:
    if len(sys.argv) >= 2:
        mailbox = sys.argv[1]
    else:
        mailbox = 'ALL'

    o = IMAPSanityFiler()
    o.run(mailbox)

    return 0

if __name__ == '__main__':
    sys.exit(main())
