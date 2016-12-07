#!/usr/bin/env python
from Crypto import Cipher
from Crypto import Random
from Crypto.Cipher import AES
import argparse
import base64
import json
import os
import six
import sys
import yaml

isPython3 = sys.version_info[0] == 3
try:
    # Python3
    from urllib.request import Request, urlopen
except ImportError:
    from urllib2 import Request, urlopen


class KeePassHTTP(object):
    @classmethod
    def from_filepath(cls, filepath, **kwargs):
        with open(filepath, 'r') as file_object:
            loaded = yaml.load(file_object.read()) or {}
            # kwargs take precedence over what is loaded
            loaded.update(kwargs)
            return cls(**loaded)

    def write_to_filepath(self, filepath):
        with open(filepath, 'w') as file_object:
            file_object.write(yaml.dump({
                'id': self.id, 'key': self.key,
            }))

    def __init__(self, port=19455, id=None, key=None):
        self.port = port
        self.key = key
        self.id = id
        self.nonce = None
        self.verifier = None  # it is always the value of Nonce encrypted with Key

    @staticmethod
    def b64encode(data):
        if isPython3:
            result = base64.b64encode(data).decode('ascii')
        else:
            result = base64.b64encode(data)

        return result

    @staticmethod
    def b64decode(data):
        return base64.b64decode(data)

    def _generate_verifier(self):
        return self._encrypt_data(self.b64encode(self.nonce))

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
            return self._response_verfier(response)
        return False

    def _encrypt_data(self, data):
        aes = AES.new(self.key, AES.MODE_CBC, self.nonce)
        cipertext = aes.encrypt(self._aes_pad(data))
        return self.b64encode(cipertext)

    def _response_verfier(self, response):
        generate_nonce = self._decrypt_data(self.b64decode(response['Verifier']),
                                            self.b64decode(response['Nonce']))
        if isPython3:
            generate_nonce = generate_nonce.decode('ascii')
        if response['Nonce'] != generate_nonce:
            raise Exception('MEN IN MIDDLE ATTACK!')
        return True

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

    def get_logins(self, url=None):
        self.nonce = self._new_iv()  # generate new nonce before request
        request_data = {
            'RequestType': 'get-all-logins' if url is None else 'get-logins',
        }
        if url is not None:
            request_data['Url'] = self._encrypt_data(url)
        response = self._request(request_data)
        self._response_verfier(response)
        logins = []
        for entry in response['Entries']:
            name = self._decrypt_data(
                self.b64decode(entry['Name']),
                self.b64decode(response['Nonce'])
            )
            login = self._decrypt_data(
                self.b64decode(entry['Login']),
                self.b64decode(response['Nonce'])
            )
            password = self._decrypt_data(
                self.b64decode(entry['Password']),
                self.b64decode(response['Nonce'])
            )
            uuid = self._decrypt_data(
                self.b64decode(entry['Uuid']),
                self.b64decode(response['Nonce'])
            )
            logins.append({
                "name": name, "login": login, "password": password,
                "uuid": uuid,
            })
        return logins

    def _request(self, request_data=dict, key_send=False):
        if self.id:
            request_data.update({'Id': self.id})
        if self.key:
            if key_send:
                request_data.update({'Key': self.b64encode(self.key)})
            self.verifier = self._generate_verifier()
            request_data.update({
                'Nonce': self.b64encode(self.nonce),
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
        if s:
            return s[:-ord(s[-1:])]
        return ""

    @staticmethod
    def _new_iv():
        return Random.new().read(Cipher.AES.block_size)

    def _request_json(self, data=dict):  # encodes the data in json and sends it to keepass
        data.setdefault("TriggerUnlock", False)
        try:

            if isPython3:
                data = json.dumps(data).encode('ascii')
            else:
                data = json.dumps(data)

            req = Request(
                'http://localhost:' + str(self.port), data=data,
                headers={
                    "Content-Type": "application/json"
                },
            )
            resp = urlopen(req)
            data = resp.read()

            if isPython3:
                return data.decode('ascii')
            else:
                return data
        except:
            return False


DEFAULT_KEYFILE_PATH = os.path.join(os.path.expanduser('~'), '.kphttpclikey.yml')


def dump_bytestring(maybe_bs):
    if isinstance(maybe_bs, six.binary_type):
        return maybe_bs.decode('utf-8')
    else:
        raise TypeError()

def json_dumps(*args, **kwargs):
    kwargs.setdefault('default', dump_bytestring)
    return json.dumps(*args, **kwargs)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Interact with Keepass database over HTTP')
    parser.add_argument(
        '--keyfile-path', '-k', default=DEFAULT_KEYFILE_PATH,
        help='Where to store or get the id/key to interact with keepass.'
    )
    parser.add_argument(
        '--associate', '-a', action='store_true', default=False,
        help='Associate with the Keepass http server.'
    )
    parser.add_argument(
        '--url', '-u', default='', help='The url search string.',
    )
    parser.add_argument(
        '--get', '-g', action='store_true', default=False, help='Get logins.',
    )
    parser.add_argument(
        '--list', '-l', action='store_true', default=False, help='List logins.'
    )
    parser.add_argument(
        '--port', '-p', default=19455, type=int,
        help='The port over which to contact keepass.',
    )
    args = parser.parse_args()
    client = None

    if args.associate:
        client = KeePassHTTP(port=args.port)
        client.associate()
        client.write_to_filepath(args.keyfile_path)
    else:
        if not os.path.exists(args.keyfile_path):
            raise Exception('please use -a associate database first')
            sys.exit(1)
        else:
            client = KeePassHTTP.from_filepath(args.keyfile_path)

    if args.get:
        if not client.is_associate():
            raise Exception('Unable to associate with server')
        print(json_dumps(client.get_logins(args.url)))
    elif args.list:
        print(json_dumps(client.get_logins()))
