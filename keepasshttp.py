#!/usr/bin/env python2
import urllib2
import json
import base64
from Crypto import Cipher
from Crypto import Random
from Crypto.Cipher import AES


class KeePassHTTP:
    def __init__(self, port=19455, id=None, key=None):
        self.port = port
        self.key = key
        self.id = id
        self.nonce = None
        self.verifier = None  # it is always the value of Nonce encrypted with Key
        ''

    def _generate_verifier(self):
        return self._encrypt_data(base64.b64encode(self.nonce))

    def is_running(self):
        try:
            request_data = {'RequestType': 'test-associate'}
            self._request(request_data)
            return True
        except:
            return False

    def is_associate(self):
        self.nonce = self._new_iv()  # generate new nonce before request
        request_data = {'RequestType': 'test-associate'}
        response = self._request(request_data)
        if response['Success']:
            self._response_verfier(response)
            return True
        else:
            return False

    def _encrypt_data(self, data):
        aes = AES.new(self.key, AES.MODE_CBC, self.nonce)
        cipertext = aes.encrypt(self._aes_pad(data))
        return base64.b64encode(cipertext)

    def _response_verfier(self, response):
        generate_nonce = self._decrypt_data(base64.b64decode(response['Verifier']),
                                            base64.b64decode(response['Nonce']))
        if response['Nonce'] == generate_nonce:
            return True
        else:
            raise Exception('MEN IN MIDDLE ATTACK!')

    def _decrypt_data(self, data, iv):
        aes = AES.new(self.key, AES.MODE_CBC, iv)
        text = self._aes_unpad(aes.decrypt(data))
        return text

    def associate(self):
        self.key = self._new_iv()
        self.nonce = self._new_iv()  # generate new nonce before request
        request_data = {'RequestType': 'associate'}
        data = self._request(request_data, True)
        if not data['Success']:
            raise Exception('lolnope')

        self._response_verfier(data)
        self.id = data['Id']

    def get_logins(self, url):
        self.nonce = self._new_iv()  # generate new nonce before request
        request_data = {'RequestType': 'get-logins',
                        'Url': self._encrypt_data(url)}
        response = self._request(request_data)
        self._response_verfier(response)
        logins = []
        for entry in response['Entries']:
            name = self._decrypt_data(base64.b64decode(entry['Name']), base64.b64decode(response['Nonce']))
            login = self._decrypt_data(base64.b64decode(entry['Login']), base64.b64decode(response['Nonce']))
            password = self._decrypt_data(base64.b64decode(entry['Password']), base64.b64decode(response['Nonce']))
            logins.append([name, login, password])
        return logins

    def _request(self, request_data=dict, key_send=False):
        if self.id:
            request_data.update({'id': self.id})
        if self.key:
            if key_send:
                request_data.update({'Key': base64.b64encode(self.key)})
            self.verifier = self._generate_verifier()
            request_data.update({
                'Nonce': base64.b64encode(self.nonce),
                'Verifier': self.verifier
            })
        resp = self._request_json(request_data)
        if not resp:
            raise Exception('Is keepasshttp running?')
        return json.loads(resp)

    @staticmethod
    def _aes_pad(data):
        pad_len = 16 - len(data) % 16
        pad_chr = chr(pad_len)
        return data + (pad_chr * pad_len)

    @staticmethod
    def _aes_unpad(s):
        return s[:-ord(s[len(s) - 1:])]

    @staticmethod
    def _new_iv():
        return Random.new().read(Cipher.AES.block_size)

    def _request_json(self, data=dict):  # encodes the data in json and sends it to keepass
        try:
            req = urllib2.Request('http://localhost:' + str(self.port), data=json.dumps(data))
            resp = urllib2.urlopen(req)
            data = resp.read()
            return data
        except:
            return False

