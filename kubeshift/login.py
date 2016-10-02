"""Perform Authentication."""
import logging

import requests
import six.moves.urllib.parse as url_parse

from kubeshift.constants import LOGGER_DEFAULT
from kubeshift.exceptions import KubeAuthFailedError

logger = logging.getLogger(LOGGER_DEFAULT)


def _parse_implicit_token(uri):
    fragment = url_parse.urlparse(uri).fragment
    params = dict(url_parse.parse_qsl(fragment, keep_blank_values=True))

    if 'error' in params:
        return None, {
            'error': params.get('error'),
            'description': params.get('error_description'),
            'uri': params.get('error_uri')
        }

    if 'token_type' not in params:
        return None, {
            'error': 'missing_token_type',
            'description': 'Missing token type parameter.',
            'uri': uri
        }

    token = params.get('access_token')
    if not token:
        return None, {
            'error': 'missing_access_token',
            'description': 'Missing access token parameter.',
            'uri': uri
        }

    return token, None


def _request_token(base_url, username, password):
    auth = (username, password)
    params = {
        'response_type': 'token',
        'client_id': 'openshift-challenging-client'
    }

    logger.warning('CAUTION: TLS verification has been DISABLED')
    requests.packages.urllib3.disable_warnings()

    # do not follow redirects as the Location is not meant to be redirected
    # to but to be parsed for the token as part of the implicit response flow.
    resp = requests.get(
        base_url + '/oauth/authorize',
        auth=auth,
        params=params,
        allow_redirects=False,
        verify=False
    )

    token = None
    if resp.ok:
        loc = resp.headers.get('location')
        if loc:
            token, err_kwargs = _parse_implicit_token(loc)
            if err_kwargs:
                raise KubeAuthFailedError('%s: %s' % (err_kwargs['error'], err_kwargs['description']))
        else:
            raise KubeAuthFailedError('Invalid response for token request')
    else:
        raise KubeAuthFailedError('Token request failed: %s' % resp.reason)

    return token


class LoginMixin(object):
    """Provide ability to authenticate into the cluster."""

    def login(self, username, password):
        """Acquire token via basic auth.

        :param str username: the user's login name
        :param str password: the user's password
        :raises kubeshift.exceptions.KubeAuthFailedError: if authentication fails
        """
        if not username or not password:
            raise KubeAuthFailedError('Missing username or password')

        token = _request_token(self.base_url, username, password)
        self.kubeconfig.set_credentials(None, token=token)

        req_inputs = self.kubeconfig.format_session()
        resp = requests.get(self.base_url + '/oapi/v1/users/~', **req_inputs)

        if resp.ok:
            # save/update the config file
            self.kubeconfig.write_file()
        else:
            raise KubeAuthFailedError('Login failed: %s' % resp.reason)
