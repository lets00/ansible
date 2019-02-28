#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (c) 2019, Luis Eduardo <leduardo@lsd.ufcg.edu.br>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: iproute2_netns
author:
    - Luis Eduardo (@lets00)
short_description: Manage all network namespaces using iproute2 module.
version_added: "2.8"
description:
    - This module allows to manage network namespaces configurations using iproute2 tool.
      You can create/remove several network namespaces.
options:
    name:
        description:
            - Name of interface that operations will be realized.
        required: true
    link:
        description:
            - Process network namespace management.
              C(present) creates a new network namespace.
              C(absent) removes a existent namespace.
        choices: [ present, absent ]
        required: true
requirements: [ pyroute2 ]
notes:
    - Online iproute2 Manpage
'''

EXAMPLES = '''
# This module can execute more than one network operation using a unique role.
# Create new veth interface, define ipv4 address and MTU (ip command):

# create a namespace (ip command)
# # ip netns add red
# In this case, veth1 will be deleted too (veth interface must de exist in pair)

- name: Create red network namespace...
  iproute2_netns:
    name: red
    link: present

# Remove a namespace
- name: Create red network namespace
  iproute2_netns:
    name: red
    link: absent
'''

from ansible.module_utils.basic import AnsibleModule
try:
    from pyroute2 import netns
    HAS_PYROUTE2 = True
except:
    HAS_PYROUTE2 = False


def main():
    argument_spec = {
        'name': {'required': True},
        'link': {'choices': ['present', 'absent'],
                 'required': True}
    }

    module = AnsibleModule(argument_spec, supports_check_mode=True)
    if not HAS_PYROUTE2:
        module.fail_json(msg='pyroute2 required for this module')

    if module.params.get('link') == 'present':
        try:
            netns.create(module.params.get('name'))
            module.exit_json(changed=True, msg=' netns {0} created'.format(module.params.get('name')))
        except OSError as os:
            # File exist
            if os.errno == 17:
                module.exit_json(changed=False)
            else:
                module.fail_json(msg='netns {0}: {1}'.format(module.params.get('name')))
    else:
        try:
            netns.remove(module.params.get('name'))
            module.exit_json(changed=True, msg=' netns {0} removed'.format(module.params.get('name')))
        except OSError as os:
            # File does not exist
            if os.errno == 2:
                module.exit_json(changed=False)
            module.fail_json(msg='Netns {0}: {1}'.format(module.params.get('name'),
                                                         os.strerror))


if __name__ == '__main__':
    main()
