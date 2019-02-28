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
module: iproute2_address
author:
    - Luis Eduardo (@lets00)
short_description: Manage network address in a specifc network interface using iproute2 tool.
version_added: "2.8"
description:
    - This module allows to add or remove network addresses in a specifc network interface
      using iproute2 tool.
options:
    interface:
        description:
            - Interface name that operations will be realized.
        required: true
    link:
        description:
            - C(present) add a network address in a network interface.
              C(absent) remove a network address in a network interface.
              C(flush) remove all network address in a network interface.
        choices: [ present, absent, flush]
        required: true
    address:
        description:
            - Ip addressess. IP (v4 or v6) address on a specific interface.
              It must be expressed using CIDR (10.0.0.1/8). Not required if C(flush) options is used.
        required: false
        type: list
requirements: [ pyroute2 ]
notes:
    - Online iproute2 Manpage
'''

EXAMPLES = '''
# Add 2 network address to an interface
- name: Add an network address to veth0 interface
  iproute2_address:
    interface: veth0
    link: present
    address: ['192.168.0.1/24','192.168.0.2/24']

# Remove an network address of veth0 interface
- name: Remove veth0 network address
  iproute2_address:
    interface: veth0
    link: absent
    address: ['192.168.0.1/24']

# Remove all network address of an interface
- name: Flush veth0 network addresses
  iproute2_address:
    interface: veth0
    link: flush
'''

from ansible.module_utils.basic import AnsibleModule
import socket
try:
    from pyroute2 import IPDB, NetlinkError
    HAS_PYROUTE2 = True
except:
    HAS_PYROUTE2 = False


def main():
    argument_spec = {
        'interface': {'required': True},
        'link': {'choices': ['present', 'absent', 'flush'],
                 'required': True},
        'address': {'required': False,
                    'type': 'list'}
    }

    required_if = [['link', 'present', ['address']],
                   ['link', 'absent', ['address']]
                   ]

    module = AnsibleModule(argument_spec,
                           required_if=required_if,
                           supports_check_mode=True)
    if not HAS_PYROUTE2:
        module.fail_json(msg='pyroute2 required for this module')
    ipdb = IPDB()
    if module.params.get('link') == 'present':
        try:
            added_adderesses = []
            # get ips on interface
            iface_addr = []
            for addr in ipdb.interfaces[module.params.get('interface')]['ipaddr']:
                iface_addr.append('{0}/{1}'.format(addr[0], addr[1]))

            for addr in module.params.get('address'):
                with ipdb.interfaces[module.params.get('interface')] as iface:
                    if addr not in iface_addr:
                        iface.add_ip(addr)
                        added_adderesses.append(addr)
            if added_adderesses:
                module.exit_json(changed=True,
                                 msg='Interface {0}, Added addresses: {1}'.format(module.params.get('interface'),
                                                                                  added_adderesses))
            module.exit_json(changed=False)
        except socket.error as skerr:
            module.fail_json(msg=skerr.args[0])
        except KeyError as k:
            module.fail_json(msg='Interface {0} does not exist.'.format(k.args[0]))
        except NetlinkError as neterr:
            if neterr.code == 105:
                module.fail_json(msg='Interface {0} does not support ip address: {1}'.format(module.params.get('name'),
                                                                                             neterr.args[1]))
    elif module.params.get('link') == 'absent':
        try:
            removed_addresses = []
            # get interface ips
            iface_addr = []
            for addr in ipdb.interfaces[module.params.get('interface')]['ipaddr']:
                iface_addr.append('{0}/{1}'.format(addr[0], addr[1]))

            for addr in module.params.get('address'):
                with ipdb.interfaces[module.params.get('interface')] as iface:
                    if addr in iface_addr:
                        iface.del_ip(addr)
                        removed_addresses.append(addr)
            if removed_addresses:
                module.exit_json(changed=True, msg='Interface {0}, '
                                                   'Removed addresses: {1}'.format(module.params.get('name'),
                                                                                   removed_addresses))
            module.exit_json(changed=False)
        except socket.error as skerr:
            module.fail_json(msg=skerr.args[0])
        except KeyError as k:
            module.fail_json(msg='Interface {0} does not exist.'.format(k.args[0]))
    else:
        if module.params.get('address'):
            module.fail_json(msg='Flush link option must not be used with address option')
        try:
            # get interface ips
            iface_addr = []
            for addr in ipdb.interfaces[module.params.get('interface')]['ipaddr']:
                iface_addr.append('{0}/{1}'.format(addr[0], addr[1]))
            with ipdb.interfaces[module.params.get('interface')] as iface:
                for addr in iface_addr:
                    iface.del_ip(addr)
            if iface_addr:
                module.exit_json(changed=True, msg='Interface {0} flushed'.format(iface))
            module.exit_json(changed=False)
        except KeyError as k:
            module.fail_json(msg='Interface {0} does not exist.'.format(k.args[0]))


if __name__ == '__main__':
    main()
