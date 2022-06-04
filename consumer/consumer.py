import boto3
import traceback
import json
from email.utils import formataddr
from smtplib import SMTP_SSL
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

def send_email(name, email):
    # Replace sender@example.com with your "From" address.
    # This address must be verified.
    SENDER = 'johndoe@johndoe.com'
    SENDERNAME = 'John Doe'

    # Replace recipient@example.com with a "To" address. If your account
    # is still in the sandbox, this address must be verified.
    RECIPIENT = email

    # Replace smtp_username with your Amazon SES SMTP user name.
    USERNAME_SMTP = "<AWS ASSIGNED SMTP USER NAME>"

    # Replace smtp_password with your Amazon SES SMTP password.
    PASSWORD_SMTP = "<AWS ASSIGNED SMTP PASSWORD>"

    # (Optional) the name of a configuration set to use for this message.
    # If you comment out this line, you also need to remove or comment out
    # the "X-SES-CONFIGURATION-SET:" header below.
    # CONFIGURATION_SET = "ConfigSet"

    # If you're using Amazon SES in an AWS Region other than US West (Oregon),
    # replace email-smtp.us-west-2.amazonaws.com with the Amazon SES SMTP
    # endpoint in the appropriate region.
    HOST = "email-smtp.eu-north-1.amazonaws.com"
    PORT = 465

    # The subject line of the email.
    SUBJECT = 'Email delivery microservice'

    # The email body for recipients with non-HTML email clients.
    BODY_TEXT = (f"Hello {name} here your email!")

    # The HTML body of the email.
    BODY_HTML = f"""<html>
    <head></head>
    <body>
    <p>Hello {name} here your email!</p>
    </body>
    </html>"""

    # Create message container - the correct MIME type is multipart/alternative.
    msg = MIMEMultipart('alternative')
    msg['Subject'] = SUBJECT
    msg['From'] = formataddr((SENDERNAME, SENDER))
    msg['To'] = RECIPIENT
    # Comment or delete the next line if you are not using a configuration set
    # msg.add_header('X-SES-CONFIGURATION-SET',CONFIGURATION_SET)

    # Record the MIME types of both parts - text/plain and text/html.
    part1 = MIMEText(BODY_TEXT, 'plain')
    part2 = MIMEText(BODY_HTML, 'html')

    # Attach parts into message container.
    # According to RFC 2046, the last part of a multipart message, in this case
    # the HTML message, is best and preferred.
    msg.attach(part1)
    msg.attach(part2)

    # Try to send the message.
    try:
        with SMTP_SSL(HOST, PORT) as server:
            server.login(USERNAME_SMTP, PASSWORD_SMTP)
            server.sendmail(SENDER, RECIPIENT, msg.as_string())
            server.close()
            print("Email sent!")
    except:
        error = traceback.format_exc()
        print(f"Failed because of {error}")


def main():
    # Create SQS client
    region = "eu-north-1"
    sqs = boto3.client('sqs', region_name=region)


    queue_url = "https://sqs.<region-name>.amazonaws.com/<account-id>/email-queue"
    # Long poll for message on provided SQS queue
    while True:
        response = sqs.receive_message(
            QueueUrl=queue_url,
            AttributeNames=[
                'SentTimestamp'
            ],
            MaxNumberOfMessages=10,
            MessageAttributeNames=[
                'All'
            ],
            WaitTimeSeconds=20
        )
        try:
            if "Messages" in response:
                for message in response['Messages']:
                    
                
                    response = json.loads(message['Body'])
                    receipt = message['ReceiptHandle']
                    name = response['name']
                    email = response['email']
                    send_email(name, email)
                    print(f"Deleting message with id: {receipt}")
                    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=receipt)
        except:
            error = traceback.format_exc()
            print(f"Failed because of {error}")
            continue


if __name__ == "__main__":
    main()