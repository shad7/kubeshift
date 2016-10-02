from __future__ import print_function
import unittest

from mock import patch
import requests
import six.moves.urllib.parse as url_parse

from kubeshift.config import Config
from kubeshift.exceptions import KubeAuthFailedError
from kubeshift.openshift import OpenshiftClient

import helper

BASE_URI = 'http://localhost:8080/oauth/token'


def make_url(base, data):
    url = base
    parts = []
    for x in data:
        parts.append('{}={}'.format(x, data[x]))
    return url + '&'.join(parts)


class TestLogin(unittest.TestCase):

    def setUp(self):
        patched_test_connection = patch.object(OpenshiftClient, '_test_connection', side_effect=helper.test_connection)
        self.addCleanup(patched_test_connection.stop)
        self.mock_tc = patched_test_connection.start()

        patched_get_groups = patch.object(OpenshiftClient, '_get_groups', side_effect=helper.get_groups)
        self.addCleanup(patched_get_groups.stop)
        self.mock_groups = patched_get_groups.start()

        patched_get_resources = patch.object(OpenshiftClient, '_get_resources', side_effect=helper.get_resources)
        self.addCleanup(patched_get_resources.stop)
        self.mock_resources = patched_get_resources.start()

    def test_missing_password(self):
        client = OpenshiftClient(None)

        with self.assertRaises(KubeAuthFailedError):
            client.login(None, None)

    def test_failed_request(self):
        client = OpenshiftClient(None)

        with patch.object(requests, 'get', side_effect=requests.exceptions.ConnectionError):
            with self.assertRaises(requests.exceptions.ConnectionError):
                client.login('admin', 'admin')

    def test_request_error(self):
        client = OpenshiftClient(None)

        with patch.object(requests, 'get', return_value=helper.make_response(400, None)):
            with self.assertRaises(KubeAuthFailedError):
                client.login('admin', 'admin')

    def test_invalid_response(self):
        client = OpenshiftClient(None)

        with patch.object(requests, 'get', return_value=helper.make_response(302, {'headers': {}})):
            with self.assertRaises(KubeAuthFailedError):
                client.login('admin', 'admin')

    def test_auth_error_response(self):
        client = OpenshiftClient(None)

        data = {
            'error': 'invalid_client',
            'error_description': 'invalid_client',
            'error_uri': BASE_URI
        }
        auth_error = {
            'location': make_url(BASE_URI + '/implicit#', data)
        }

        with patch.object(requests, 'get', return_value=helper.make_response(302, None, auth_error)):
            with self.assertRaises(KubeAuthFailedError):
                client.login('admin', 'admin')

    def test_no_token_type_error(self):
        client = OpenshiftClient(None)

        data = {
            'access_token': 'ZDNCAwfCIJyZQWvCZkp4wp6p7zXJ3CNwLKYKWE3UwgM',
            'expires_in': '86400',
            'scope': 'user:full'
        }
        auth_error = {
            'location': make_url(BASE_URI + '/implicit#', data)
        }

        with patch.object(requests, 'get', return_value=helper.make_response(302, None, auth_error)):
            with self.assertRaises(KubeAuthFailedError):
                client.login('admin', 'admin')

    def test_no_access_token(self):
        client = OpenshiftClient(None)

        data = {
            'expires_in': '86400',
            'scope': 'user:full',
            'token_type': 'Bearer'
        }
        auth_error = {
            'location': make_url(BASE_URI + '/implicit#', data)
        }

        with patch.object(requests, 'get', return_value=helper.make_response(302, None, auth_error)):
            with self.assertRaises(KubeAuthFailedError):
                client.login('admin', 'admin')

    def test_token_found_login_fails(self):
        client = OpenshiftClient(None)

        data = {
            'access_token': 'ZDNCAwfCIJyZQWvCZkp4wp6p7zXJ3CNwLKYKWE3UwgM',
            'expires_in': '86400',
            'scope': 'user:full',
            'token_type': 'Bearer'
        }
        auth_resp = {
            'location': make_url(BASE_URI + '/implicit#', data)
        }

        def respond(*args, **kwargs):
            if args[0] == 'http://localhost:8080/oapi/v1/users/~':
                return helper.make_response(401, None)
            return helper.make_response(302, None, auth_resp)

        with patch.object(requests, 'get', side_effect=respond):
            with self.assertRaises(KubeAuthFailedError):
                client.login('admin', 'admin')

    def test_login_successful(self):
        client = OpenshiftClient(None)

        data = {
            'access_token': 'ZDNCAwfCIJyZQWvCZkp4wp6p7zXJ3CNwLKYKWE3UwgM',
            'expires_in': '86400',
            'scope': 'user:full',
            'token_type': 'Bearer'
        }
        auth_resp = {
            'location': make_url(BASE_URI + '/implicit#', data)
        }

        def respond(*args, **kwargs):
            if args[0] == 'http://localhost:8080/oapi/v1/users/~':
                return helper.make_response(200, {})
            return helper.make_response(302, None, auth_resp)

        with patch.object(requests, 'get', side_effect=respond):
            with patch.object(client.kubeconfig, 'write_file', side_effect=print):
                client.login('admin', 'admin')
