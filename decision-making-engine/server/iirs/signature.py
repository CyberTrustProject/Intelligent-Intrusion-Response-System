import os
import json
import base64
import time

from Crypto.Signature import pkcs1_15
from Crypto.Hash import MD2, MD5, SHA1, SHA256, SHA384, SHA512
from Crypto.PublicKey import RSA

PRIVATE_KEY_PATH =  os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs", "private") 
PUBLIC_KEY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs") 

def signMessage(json_message):
    with open(os.path.join(PRIVATE_KEY_PATH, "key.pem"), 'rb') as pk:
        key = RSA.import_key(pk.read())
    
    h = SHA256.new(json.dumps(json_message, separators=(',',':')).encode('utf-8'))
    signature = pkcs1_15.new(key).sign(h)
    
    return base64.b64encode(signature).decode('utf-8')

def prepareAsyncMessage(payload):
    template = {
        "header":{
            "source": "iirs1234.cybertrust.eu",
            "msg_topic": "",
            "msg_id": "",
            "cor_id": "",
            "timestamp": round(time.time()*1000),
            "sign_alg": "sha256WithRSAEncryption"
        },
        "payload": {},
    }
    template["payload"] = payload

    # payload_str = json.dumps(template, separators=(',', ':')).encode('utf-8')

    # signature = signMessage(template)
    # template["trailer"] = {
    #     "signature": signature # key is maybe "sig"
    # }

    return template
