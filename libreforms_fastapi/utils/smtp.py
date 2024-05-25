import ssl
import smtplib 
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import Header

class Mailer():
    def __init__(self, mail_server=None, port=None, 
                        username=None, password=None, 
                        from_address=None, enabled=True):

        if enabled:
            # setting up ssl context
            self.context = ssl.create_default_context()
            self.mail_server = mail_server
            self.port = port
            self.username = username
            self.password = password
            self.from_address = from_address
            self.enabled = True
        else: 
            self.enabled = False

    # borrowed shamelessly from 
    # https://www.aabidsofi.com/posts/sending-emails-with-aws-ses-and-python/
    def send_mail(
        self, 
        subject=None, 
        content=None, 
        to_address:str=None, 
        # to_address:str|list=None, 
        cc_address_list:list=[], 
        logfile=None, 
        reply_to_addr=None
    ):

        # only proceed if we have enabled SMTP
        if not self.enabled:
            return


        # We want to verify the to address
        # if isinstance(to_address, list):
        #     to_address = ", ".join(to_address)


        # We want to verify the type of the cc list
        if all([
            cc_address_list,
            isinstance(cc_address_list, list),
            len(cc_address_list)>0
        ]):
            final_cc_address_list = ", ".join(cc_address_list)
        else:
            final_cc_address_list = None

        try:
            # creating an unsecure smtp connection
            with smtplib.SMTP(self.mail_server,self.port) as server:

                msg = MIMEMultipart()
                msg['Subject'] = Header(subject, 'utf-8')
                msg['From'] = self.from_address
                msg['To'] = to_address
                msg['Cc'] = final_cc_address_list
                msg['Reply-To'] = reply_to_addr if reply_to_addr else self.from_address

                msg.attach(MIMEText(content))

                # securing using tls
                server.starttls(context=self.context)

                # authenticating with the server to prove our identity
                server.login(self.username, self.password)

                # sending a plain text email
                server.sendmail(self.from_address, [to_address]+cc_address_list, msg.as_string())
                # server.send_message(msg.as_string())

                if logfile: logfile.info(f'successfully sent an email to {to_address}')
                
                return True

        except Exception as e: 
            if logfile: logfile.error(f'could not send an email to {to_address} - {e}')
            
            return False


    def test_connection(
        self, 
        enabled=None, 
        mail_server=None, 
        port=None, 
        username=None, 
        password=None
    ):

        enabled = self.enabled if enabled is None else enabled
        mail_server = self.mail_server if mail_server is None else mail_server
        port = self.port if port is None else port
        username = self.username if username is None else username
        password = self.password if password is None else password

        if not enabled:
            return False
        
        try:
            with smtplib.SMTP(mail_server, port) as server:
                server.starttls(context=self.context)  # Start TLS encryption
                server.login(username, password)  # Attempt to log in to the SMTP server
                return True  # If login is successful, return True

        except Exception as e:
            print(f"Connection test failed: {e}")
            return False  # Return False if there are any exceptions