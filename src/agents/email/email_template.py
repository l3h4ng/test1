# -*- coding: utf-8 -*-
_author_ = 'TOANTV'
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from systems.models import SystemsEmailNotify
from requests import RequestException
from retrying import retry

class EmailTemplate:
    def __init__(self, email_subject='', email_recv=[], email_cc=[], email_bcc=[]):
        self.email_subject = email_subject
        self.email_recv = email_recv
        self.email_cc = email_cc
        self.email_bcc = email_bcc
        self.email_send = "sboxteam.2015@gmail.com"
        self.email_pwd = "jhirvjtnwdyctplo"
        self.email_host = "smtp.gmail.com"
        self.email_port = "587"
        self.email_security = "Auto"

    def get_config(self, email="", passwd="", mail_server="", port="", security=""):
        if email == "" or passwd == "" or mail_server == "" or port == "" or security == "":
            try:
                email_config = SystemsEmailNotify.objects.get(pk=1)
                if email_config.enable:
                    # Get config email send
                    if isinstance(email_config.from_address, unicode):
                        self.email_send = email_config.from_address.encode('utf-8')
                    else:
                        self.email_send = email_config.from_address

                    if isinstance(email_config.password, unicode):
                        self.email_pwd = email_config.password.encode('utf-8')
                    else:
                        self.email_pwd = email_config.password

                    if isinstance(email_config.smtp_server, unicode):
                        self.email_host = email_config.smtp_server.encode('utf-8')
                    else:
                        self.email_host = email_config.smtp_server

                    if isinstance(email_config.port, unicode):
                        self.email_port = email_config.port.encode('utf-8')
                    else:
                        self.email_port = email_config.port

                    if isinstance(email_config.security, unicode):
                        self.email_security = email_config.security.encode('utf-8')
                    else:
                        self.email_security = email_config.security
            except SystemsEmailNotify.DoesNotExist:
                pass
        else:
            self.email_send = email
            self.email_pwd = passwd
            self.email_host = mail_server
            self.email_port = port
            self.email_security = security

    def send_email(self, html_temp, args=[]):
        try:
            self.try_send_email(html_temp, args)
        except Exception, exc:
            print "Cannot send report email. Please check the config."
            return None

    @retry(wait_random_min=3000, wait_random_max=5000, stop_max_attempt_number=3)
    def try_send_email(self, html_temp, args=[]):
        content = self.replace_html(html_temp, args)

        recipient = self.email_recv + self.email_cc + self.email_bcc

        msgRoot = MIMEMultipart('related')
        msgRoot['Subject'] = self.email_subject
        msgRoot['From'] = self.email_send
        msgRoot['To'] = ','.join(self.email_recv)
        msgRoot['Cc'] = ','.join(self.email_cc)
        msgRoot['Bcc'] = ','.join(self.email_bcc)

        msgAlternative = MIMEMultipart('alternative')
        msgRoot.attach(msgAlternative)

        msgText = MIMEText(content, 'html', 'UTF-8')
        msgAlternative.attach(msgText)

        x = 1
        list_image = ['images\logo_img.png', 'images\ethernet.png', 'images\lytics.png']

        for i in list_image:
            image = os.path.join("agents", "email", i)
            fp = open(str(image), 'rb')
            msgImage = MIMEImage(fp.read())
            fp.close()

            img_name = '<image' + str(x) + '>'
            msgImage.add_header('Content-ID', img_name)
            x += 1
            msgRoot.attach(msgImage)

        try:
            if self.email_security == 'TLS':
                smtp = smtplib.SMTP(self.email_host, self.email_port)
            elif self.email_security == 'SSL':
                smtp = smtplib.SMTP_SSL(self.email_host, self.email_port)
            elif self.email_security == 'Auto':
                try:
                    smtp = smtplib.SMTP(self.email_host, self.email_port)
                except Exception, ex:
                    smtp = smtplib.SMTP_SSL(self.email_host, self.email_port)
            else:
                smtp = smtplib.SMTP(self.email_host, self.email_port)

            smtp.ehlo()
            smtp.starttls()
            smtp.login(self.email_send, self.email_pwd)
            smtp.sendmail(self.email_send, recipient, msgRoot.as_string())
            smtp.quit()
            print("Successfully sent email")
        except smtplib.SMTPException as e:
            print "Cannot login to email account. Please check the config. Error {}".format(str(e))
            raise RequestException("Send email error, retrying ....")
        except Exception, ex:
            print "Send email error {}. Try again.".format(str(ex))
            raise RequestException("Send email error, retrying ....")

    def send_email_finish(self, args):
        html_temp = "wvs_finish.html"

        self.send_email(html_temp, args)

    def send_email_alert(self, args):
        html_temp = "alert.html"

        self.send_email(html_temp, args)

    def send_email_scan_error(self, args):
        html_temp = "sbox4net_scan_error.html"

        self.send_email(html_temp, args)

    def read_content(self, html_temp):
        with open(html_temp, 'r') as fr:
            return fr.read()

    def replace_html(self, html_temp, args):
        html_temp_dir = os.path.join("agents", "email", "html", html_temp)
        x = 1
        html_content = self.read_content(html_temp_dir)

        for i in range(len(args)):
            if isinstance(args[i], unicode):
                html_content = html_content.replace('5SBOX{}X'.format(str(x)), args[i].encode('utf-8'))
            else:
                html_content = html_content.replace('5SBOX{}X'.format(str(x)), args[i])
            x += 1
        return html_content

# email_notify =  SboxEmail(email_subject='Test email', email_recv=['ducbvbk@gmail.com','ngocngoan060288@gmail.com'],
#                           email_cc=['nguyendacthinh1992@gmail.com','ngocngoan060288@hotmail.com'])
# email_notify.send_email('D:\PyThon\sent_mail\HTML\html_temp.html',['123.45.67.89','123.45.67.89','12','12','2','7','18'])
