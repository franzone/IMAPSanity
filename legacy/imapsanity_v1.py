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
            self.config = load(stream, Loader=Loader)#['mailboxes']

    def run(self, mailbox='ALL'):
        if 'ALL' == mailbox or mailbox in self.config.keys():
            print('Running IMAPSanityFiler against {0} mailbox(s)'.format(mailbox))
            for key in self.config:
                if 'ALL' == mailbox or key == mailbox:
                    self.filers_config = self.config[key]['filers']
                    self.matches_config = self.config[key]['matches']
                    #pprint.pprint(self.filers_config)
                    #pprint.pprint(self.matches_config)
                    self.process_mailbox(self.config[key])
        else:
            print('Mailbox {0} Not Found'.format(mailbox))

    def process_mailbox(self, mailbox):
        print('Processing mailbox for {0}'.format(mailbox['email']))
        mbox = self.open_inbox(mailbox)
        if mbox:
            try:
                # First process the INBOX
                self.file_inbox_emails(mbox)

                # Now process each of the filers
                self.process_file_folders(mbox)

            except:
                print('Error processing inbox for {0}: {1}'.format(mailbox['email'], sys.exc_info()[0]))
                print(traceback.format_exc())
            finally:
                if mbox is not None:
                    self.close_inbox(mbox)

    def file_inbox_emails(self, mbox):
        print('\nProcessing INBOX to file emails...')
        try:
            mbox.select()
        except:
            print('Error processing email', sys.exc_info()[0])
            print(traceback.format_exc())
            
        for i in range(len(self.matches_config)):
            matchCfg = self.matches_config[i]
            filerCfg = self.filers_config[matchCfg['filer']]
            if filerCfg is not None and 'folder' in filerCfg and filerCfg['folder'] is not None:
                # build an IMAP search - now returns UIDs
                typ, data = self.search_for_match(mbox, matchCfg)
                
                # UIDs are returned as space-separated bytes
                uid_list = data[0].split()
                totalCount = len(uid_list)
                print('Found {0} emails to process'.format(totalCount))
                
                if totalCount == 0:
                    continue
                
                # Batch operations for better performance
                uids_to_move = []
                counter = 0
                
                for uid in uid_list:
                    try:
                        # Fetch only headers (much faster than full message)
                        typ, data = mbox.uid('FETCH', uid, '(BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)])')
                        
                        if typ != 'OK' or not data or data[0] is None:
                            continue
                            
                        # Parse the header
                        header_bytes = data[0][1]
                        msg = email.message_from_bytes(header_bytes, policy=email.policy.default)

                        # Get JUST the email address and domain
                        match = re.search(r'([\w\.-]+)(@[\w\.-]+)', msg['From'])
                        emailAddr = msg['From']
                        if match is not None:
                            emailAddr = match.group(0)

                        action = 'MOVING'

                        uids_to_move.append(uid)
                        counter = counter + 1

                        print('{0} - {1} - {2} - {3}'.format(action, msg['Date'], emailAddr, self.strip_non_ascii(msg['Subject'])))
                    except:
                        print('Error processing email', sys.exc_info()[0])
                        print(traceback.format_exc())

                # Batch copy and delete operations
                if uids_to_move:
                    try:
                        # Create comma-separated UID list for batch operations
                        uid_set = b','.join(uids_to_move)
                        
                        # Use COPY instead of APPEND (much faster, preserves metadata)
                        mbox.uid('COPY', uid_set, filerCfg['folder'])
                        
                        # Mark for deletion
                        mbox.uid('STORE', uid_set, '+FLAGS', '\\Deleted')
                        
                        # Expunge to actually delete
                        mbox.expunge()
                        
                        print('Moved {0} emails to {1}'.format(counter, filerCfg['folder']))
                    except:
                        print('Error in batch operations', sys.exc_info()[0])
                        print(traceback.format_exc())

    def process_file_folders(self, mbox):
        print('\nProcessing filer folders...')
        for filerKey, cfg in self.filers_config.items():
            if cfg['keepAll'] != True:
                print('Processing filer : {0}'.format(filerKey))
                cfgKeep = cfg['keep']
                if not isinstance(cfgKeep, int):
                    print('ERROR: Configured value [keep][{0}] is not an integer', cfgKeep)
                else:
                    mbox.select(cfg['folder'])

                    pprint.pprint(cfg)
                    for i in range(len(self.matches_config)):
                        if self.matches_config[i]['filer'] == filerKey:
                            matchCfg = self.matches_config[i]

                            # build an IMAP search - now returns UIDs
                            typ, data = self.search_for_match(mbox, matchCfg)
                            
                            # UIDs are returned as space-separated bytes
                            uid_list = data[0].split()
                            totalCount = len(uid_list)
                            print('Found {0} emails to process'.format(totalCount))
                            
                            if totalCount == 0:
                                continue
                            
                            counter = 0
                            uids_to_delete = []
                            
                            for uid in uid_list:
                                counter = counter + 1
                                try:
                                    # Fetch only headers (much faster than full message)
                                    typ, data = mbox.uid('FETCH', uid, '(BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)])')
                                    
                                    if typ != 'OK' or not data or data[0] is None:
                                        continue
                                        
                                    # Parse the header
                                    header_bytes = data[0][1]
                                    msg = email.message_from_bytes(header_bytes, policy=email.policy.default)

                                    # Get JUST the email address and domain
                                    match = re.search(r'([\w\.-]+)(@[\w\.-]+)', msg['From'])
                                    emailAddr = msg['From']
                                    if match is not None:
                                        emailAddr = match.group(0)

                                    action = 'KEEPING'
                                    if counter > cfgKeep:
                                        action = 'DELETING'
                                        uids_to_delete.append(uid)

                                    print('{0} - {1} - {2} - {3}'.format(action, msg['Date'], emailAddr, self.strip_non_ascii(msg['Subject'])))

                                except:
                                    print('Error processing email', sys.exc_info()[0])
                                    print(traceback.format_exc())

                            # Batch delete operations
                            if uids_to_delete:
                                try:
                                    # Create comma-separated UID list
                                    uid_set = b','.join(uids_to_delete)
                                    
                                    # Mark for deletion
                                    mbox.uid('STORE', uid_set, '+FLAGS', '\\Deleted')
                                    
                                    # Expunge to actually delete
                                    mbox.expunge()
                                except:
                                    print('Error in batch delete operations', sys.exc_info()[0])
                                    print(traceback.format_exc())
                            
                            print(' ')

    def search_for_match(self, mbox, matchCfg):
        """
        Performs IMAP search using UID SORT for better performance.
        Returns UIDs instead of sequence numbers for reliability.
        """
        cfgSender = None
        cfgSubject = None
        if 'sender' in matchCfg:
            cfgSender = matchCfg['sender']
        if 'subject' in matchCfg:
            cfgSubject = matchCfg['subject']

        # Build search criteria
        search_criteria = []
        
        if cfgSender is not None and cfgSender != '':
            search_criteria.append('(FROM "' + cfgSender + '")')
        
        if cfgSubject is not None and cfgSubject != '':
            search_criteria.append('(SUBJECT "' + cfgSubject + '")')
        
        # Combine criteria
        if len(search_criteria) == 0:
            # Fallback to ALL if no criteria
            search_criteria.append('ALL')
        
        # Use UID SORT instead of SORT for UIDs
        try:
            # Try with multiple criteria
            if len(search_criteria) > 1:
                result = mbox.uid('SORT', '(REVERSE DATE)', 'UTF-8', *search_criteria)
            else:
                result = mbox.uid('SORT', '(REVERSE DATE)', 'UTF-8', search_criteria[0])
            return result
        except:
            # Fallback to UID SEARCH if SORT is not supported
            print('SORT not supported, falling back to SEARCH')
            if len(search_criteria) > 1:
                result = mbox.uid('SEARCH', None, *search_criteria)
            else:
                result = mbox.uid('SEARCH', None, search_criteria[0])
            return result

    def email_matches(self, configEmail, actualEmail):
        if configEmail.startswith('@'):
            if actualEmail.endswith(configEmail):
                return True
        if configEmail == actualEmail:
            return True
        return False

    def subject_matches(self, configSubject, actualSubject):
        if configSubject is None or configSubject == '':
            return True
        if actualSubject is None or actualSubject == '':
            return False
        if configSubject in actualSubject:
            return True
        return False

    def open_inbox(self, mailbox):
        mbox = imaplib.IMAP4(mailbox['imapHost'])
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
