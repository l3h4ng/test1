import smtplib
import time

# from common.logger import logger

def connect_to_mail(smtp):
    count = 0
    while True:
        try:
            if smtp.security == 'TLS':
                server = smtplib.SMTP(smtp.smtp_server, smtp.port)
            elif smtp.security == 'SSL':
                server = smtplib.SMTP_SSL(smtp.smtp_server, smtp.port)
            elif smtp.security == 'Auto':
                try:
                    server = smtplib.SMTP(smtp.smtp_server, smtp.port)
                except Exception, ex:
                    server = smtplib.SMTP_SSL(smtp.smtp_server, smtp.port)
            else:
                smtp.test_connection = False
                smtp.save()
                return smtp
            server.ehlo()
            try:
                server.starttls()
            except Exception, ex:
                pass
            if smtp.username is not None and smtp.password is not None:
                server.login(smtp.username,(smtp.password))#.decode("rot13"))
            smtp.test_connection = True
            smtp.save()
            print ("Connect win!")
            return smtp
        except Exception, err:
            print ("Can not login to SMTP server: %s " % err)
            if count < 3:
                print ("Trying login to SMTP server ... ")
                count += 1
            else:
                print ("Connect fail!")
                smtp.test_connection = False
                smtp.save()
                return smtp
            time.sleep(1)
