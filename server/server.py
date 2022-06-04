from flask import Flask, request
import boto3
import json


app = Flask(__name__)

@app.route('/api', methods=['GET'])
def api():
    args = request.args
    name = args.get("name")
    email = args.get("email")
    if not name or not email:
        return "<p>Set parameters</p>"
    post_query(name, email)
    return "<p>Your queue request was successful</p>"


def post_query(name, email):
    
    message = {
        "name": name,
        "email": email
    }
    sqs = boto3.client('sqs')

    print(f"About to upload message {message}")
    response = sqs.send_message(
        QueueUrl="https://sqs.<region-name>.amazonaws.com/<account-id>/email-queue",
        MessageBody=json.dumps(message)
    )
    
    
if __name__ == '__main__':
      app.run(host='0.0.0.0', port=80)

        