# IMAPSanity
A Python script to add some sanity to my Email Inbox (via IMAP). I find that I get tons of emails from the same sender, but they pile up so quickly that I don't have time to view them all. It's not that I don't want emails from that sender at all, but I don't need all of them. This script will help me to keep the last X messages from a sender, or keep them all. After matching, it moves them to a filtered folder/INBOX so that I can view them there.

## Configuration
Configure as many mailboxes as you need to process in the `mailboxes.yml` configuration file. You may copy `mailboxes_sample.yml` to `mailboxes.yml` and then modify appropriately. The format is as follows:

```
mailboxes:
  john:
    email: john.doe@gmail.com
    password: 123456
    imap-host: imap.sample.com
    spam-folder: INBOX.Spam
  jane:
    email: jane.doe@gmail.com
    password: 789101
    imap-host: imap.sample.com
    spam-folder: INBOX.Spam
```
\* *Obviously you will need to modify the configuration in `mailboxes.yml` to meet your personal needs (i.e., the configuration of your IMAP mailboxes).*

## Running the Script
To run all configurations:
```
python imapsanity.yml
```

To run a specific configuration:
```
python imapsanity.yml john
```

### Running Using a Cron Job
* First clone the repository: git clone https://github.com/franzone/IMAPSanity.git MeSpam
* Second, copy IMAPSanity/mailboxes_sample.yml to IMAPSanity/mailboxes.yml
* Third, modify IMAPSanity/mailboxes.yml appropriately (using your real email)
* Finally, create a crontab entry to run it:
```
# Runs every 15 minutes
*/15 * * * * cd $HOME/IMAPSanity && python3 imapsanity.py
```

## Requirements
* Python >= 3.10
* IMAP account that allows remote authentication using **email address** and **password**

## Terms and Conditions
Download and use of any content (files, scripts, images, etc.) from the repository located at https://github.com/franzone/IMAPSanity construes your consent to these **Terms and Conditions**. Use of this script or any related files is at your own risk. The author, Jonathan Franzone, his family, friends or associates, may not be held liable for any damages, imagined or real, caused by your use of this script or related files.

## Author
The author of this script is Jonathan Franzone (that's me!). You can find more information about him at:
* https://franzone.blog
* https://about.franzone.com
* https://www.linkedin.com/in/jonathanfranzone/

## License
[MIT License](LICENSE)