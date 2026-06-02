#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = """
    name: secretd
    author: secretd authors
    short_description: Fetch secrets from a secretd vault.
    description:
        - Retrieves a secret payload from a running secretd instance via its HTTP API.
    options:
        _terms:
            description: The key path of the secret to retrieve (e.g. 'app.db.password').
            required: True
    notes:
        - Requires the SECRETD_URL environment variable to point to the API base URL (e.g., http://localhost:8090).
        - Requires the SECRETD_TOKEN environment variable containing an authorized machine token.
"""

EXAMPLES = """
- name: Set environment variable from secretd
  ansible.builtin.debug:
    msg: "The password is {{ lookup('secretd', 'app.db.password') }}"
"""

RETURN = """
  _raw:
    description:
      - The decrypted string value of the secret.
    type: list
"""

import os
import urllib.request
import urllib.error
import json

from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase

class LookupModule(LookupBase):

    def run(self, terms, variables=None, **kwargs):
        api_url = os.environ.get('SECRETD_URL')
        if not api_url:
            raise AnsibleError("SECRETD_URL environment variable is required.")
        
        token = os.environ.get('SECRETD_TOKEN')
        if not token:
            raise AnsibleError("SECRETD_TOKEN environment variable is required.")

        # Ensure no trailing slash
        api_url = api_url.rstrip('/')

        ret = []

        for term in terms:
            url = f"{api_url}/v1/secrets/{term}"
            req = urllib.request.Request(url)
            req.add_header('Authorization', f'Bearer {token}')

            try:
                with urllib.request.urlopen(req) as response:
                    if response.status != 200:
                        raise AnsibleError(f"secretd returned status {response.status} for key '{term}'")
                    
                    data = json.loads(response.read().decode('utf-8'))
                    if 'value' not in data:
                        raise AnsibleError(f"Unexpected response format from secretd for key '{term}'")
                    
                    ret.append(data['value'])

            except urllib.error.HTTPError as e:
                if e.code == 404:
                    raise AnsibleError(f"Secret '{term}' not found in secretd.")
                elif e.code == 403:
                    raise AnsibleError(f"Access denied to secret '{term}'. Check token policies.")
                else:
                    raise AnsibleError(f"HTTP Error fetching '{term}': {e.code} {e.reason}")
            except urllib.error.URLError as e:
                raise AnsibleError(f"Failed to connect to secretd at {api_url}: {e.reason}")
            except json.JSONDecodeError:
                raise AnsibleError(f"Failed to parse JSON response from secretd for key '{term}'")

        return ret
