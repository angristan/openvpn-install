import sys
import os
import subprocess
import smtplib
from os.path import basename
from os.path import expanduser
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import COMMASPACE, formatdate

send_to = ''
sendConfViaEmail = False

for i in range(len(sys.argv)): #parse the given arguments
    if sys.argv[i] =="--email":
        try:
            sendConfViaEmail = True
            i+=1
            send_to = sys.argv[i]
        except:
            break

if sendConfViaEmail == False: #if there is no email argument
    with open ("temp.bash","w") as fil: #create temp.bash file
        fil.write("#!/bin/bash\n")
        fil.write("./openvpn-install.sh") #to just launch the .sh
        fil.close()
    os.system("sudo bash temp.bash") #execute temp bash
    os.system("rm temp.bash") #and remove it after

else:
    confName = send_to.split("@")[0] #if there is email argument, create confFile from it
    with open ("temp.bash","w") as fil: #create temp.bash file
        fil.write("#!/bin/bash\n")
        fil.write("export MENU_OPTION=\"1\"\n") #which is going to automatically make ovpn profile on the server
        row = "export CLIENT=\""
        row+= confName # with name based from email
        row += "\"\n"
        fil.write(row)
        fil.write("export PASS=\"1\"\n")
        fil.write("./openvpn-install.sh")
        fil.close()
        
    os.system("sudo bash temp.bash") #execute generated temp bash
    os.system("rm temp.bash") #and remove it after

    #now send that config file over email
    
    #------------------------------!!!!!----------------------------------------
    gmail_user = '' #email of your gmail account used to send file
    gmail_password = '' #email app password generated online
    #------------------------------!!!!!----------------------------------------

    msg = MIMEMultipart() #create blank email message
    msg['From'] = gmail_user
    msg['To'] = send_to #input recipient
    msg['Date'] = formatdate(localtime=True) #add current timestamp
    msg['Subject'] = 'VPN Configuration File' #add subject to message
    text ="Please proceed to download your .ovpn config file" #and text content, i.e. HTML,plain text
    msg.attach(MIMEText(text)) 

    #now move .ovpn file from home directory to current working directory
    files = confName
    files += ".ovpn"
    wd = os.getcwd()
    home = expanduser("~")
    cmd ="cd " 
    cmd += home
    cmd+=" && mv " 
    cmd+=files
    cmd+=" "   
    cmd+=wd
    os.system(cmd)

    #attach it to the message
    with open(files, "rb") as fil:
        part = MIMEApplication(
            fil.read(),
            Name=basename(files)
            )
    part['Content-Disposition'] = 'attachment; filename="%s"' % basename(files)
    msg.attach(part)

    #send email message containing .ovpn file to recipient
    server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
    server.ehlo()
    server.login(gmail_user, gmail_password)
    server.sendmail(gmail_user, send_to, msg.as_string())
    server.close()
    print('Email sent!')

    #finaly, remove config file from the system
    cmd = "rm "
    cmd += files
    os.system(cmd)
