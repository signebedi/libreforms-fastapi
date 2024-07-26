import ssl
import smtplib 
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import Header

class Mailer():
    def __init__(
        self,
        mail_server=None, 
        port=None,
        username=None, 
        password=None, 
        from_address=None, 
        enabled=True
    ):

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
        subject: None | str = None, 
        content: None | str = None, 
        to_address: str | list = [], 
        cc_address_list: str | list = [], 
        reply_to_addr: None | str = None,
        body_type: str = "plain",
        send_individually: bool = True,
        # parse_to_addr_as_list:bool=False,
    ):

        # only proceed if we have enabled SMTP
        if not self.enabled:
            return

        # Check to_address
        if not to_address:
            raise Exception("You must pass a to_addr as a string or list")

        # Cast to address as a list
        if isinstance(to_address, str):
            to_address = [to_address]
        string_to_address_list = ", ".join(to_address).strip()

        # print("\n\n\n", string_to_address_list)

        # We want to verify the type of the cc list
        if isinstance(cc_address_list, str):
            cc_address_list = [cc_address_list]
        string_cc_address_list = ", ".join(cc_address_list).strip()

        # print("\n\n\n", string_cc_address_list)

        # Generate the message content
        msg = MIMEMultipart()
        msg['Subject'] = Header(subject, 'utf-8')
        msg['From'] = self.from_address
        # msg['To'] = string_to_address_list

        if len(cc_address_list) > 0:
            msg['Cc'] = string_cc_address_list
        
        msg['Reply-To'] = reply_to_addr if reply_to_addr else self.from_address

        msg.attach(MIMEText(content, body_type, 'utf-8'))

        # In the future we may want to add support for attachments
        # part = MIMEText(file_content, body_type, 'utf-8')
        # part = MIMEText(content, 'plain', 'utf-8')
        # part.add_header('Content-Disposition', 'attachment; filename="filename.txt"')
        # msg.attach(part)


        # print("\n\n\n", msg.as_string())


        # creating an unsecure smtp connection
        with smtplib.SMTP(self.mail_server,self.port) as server:


            # securing using tls
            server.starttls(context=self.context)

            # authenticating with the server to prove our identity
            server.login(self.username, self.password)

            # if obfuscate_emails_for_recipients:
            #     for email_target in merged_email_list:

            # sending a plain text email
            # server.sendmail(self.from_address, merged_email_list, msg.as_string())
            # server.send_message(msg.as_string())

            # Sending messages individually may increase quota usage and costs, see
            # https://github.com/signebedi/libreforms-fastapi/issues/326. Note:
            # there are issues with sending to multiple recipients.
            if not send_individually:

                msg['To'] = string_to_address_list
                server.send_message(msg)

                return True

            for recipient in to_address:
                msg['To'] = recipient
                try:
                    server.send_message(msg)
                    print(f'Email sent to {recipient}')
                except smtplib.SMTPRecipientsRefused as e:
                    print(f'Failed to send email to {recipient}: {e.recipients}')
                except smtplib.SMTPException as e:
                    print(f'An SMTP error occurred while sending to {recipient}: {e}')
                except Exception as e:
                    print(f'An unexpected error occurred while sending to {recipient}: {e}')


            return True


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