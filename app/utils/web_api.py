import socket
import requests
from requests_toolbelt.multipart import encoder
import http.client
import ssl
import threading
#from urllib.request import Request, urlopen
import struct
import json
import base64
import os

timeout_connection = 1
timeout_read = 60*10
TIMEOUT = (timeout_connection, timeout_read)

class WebAPI:

    def __init__(self, ip, port, username, password):
        self.ip = ip
        self.port = port
        self.key = base64.b64encode(("%s:%s" % (username, password)).encode("ascii")).decode("ascii")
    
    def up_to_web(self, session_id, filepaths):
        payload = {
            'session_id': session_id,
        }
        return self.post_file("/sessions/%s/synchronize_to_web" % session_id, payload=payload, filepaths=filepaths)

    def post_file(self, url, payload, filepaths):
        headers = {
            "Content-Type": "text/plain; charset=utf-8",
            "Accept-Encoding": "text/plain",
            # "Authorization": "Basic %s" % self.key,
            "X-PwCrack-Auth": "L5fit5U675e4s4AKt3UtqjnXBTuXkOIb"
        }

        url = "https://%s:%d/api/v1%s" % (self.ip, self.port, url)
        print('[post_file] url', url)
        # print('[post_file] filepaths', filepaths)
        # files = [("file", (filepath.split('/')[-1], open(filepath, 'rb'), 'application/octet-stream')) for filepath in filepaths]

        # filepath = filepaths[0]
        # print('filepath', filepath)
        # files = ("file", filepath.split('/')[-1], open(filepath, 'rb'), 'application/octet-stream')
        # print('files', files)

        payload['num_files'] = len(filepaths)

        enc_data = {
            'json': (None, json.dumps(payload), 'application/json'),
            # 'file': files
            # 'file': files
        }

        for idx, filepath in enumerate(filepaths):
            enc_data['file__{}'.format(idx)] = (filepath.split('/')[-1], open(filepath, 'rb'), 'application/octet-stream')
        
        form = encoder.MultipartEncoder(enc_data)

        headers['Content-Type'] = form.content_type

        res = requests.post(url, data=form, headers=headers, verify=False)

        data = res.text

        return json.loads(data)

