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
module: iproute2_link
author:
    - Luis Eduardo (@lets00)
short_description: Manage all network interfaces using iproute2 module.
version_added: "2.8"
description:
    - This module allows manage network configurations using iproute2 tool.
      You can create/remove several types of network interfaces (veth, bridges,
      gre, vxlan, and others).
options:
    name:
        description:
            - Name of interface that operations will be realized.
        required: true
    link:
        description:
            - C(present) creates a new net interface if It does not exist. C(type) is required.
              C(absent) removes a net interface if It exist.
        choices: [ present, absent]
        required: false
    state:
        description:
            - C(up) turn on a net interface if It exist.
              C(down) turn off a net interface if It exist.
        choices [ up, down]
        required: false
    type:
        description:
            - Interface type that will be create when C(link) is present.
              C(bridge) creates a bridge interface.
              C(dummy) creates a dummy interface. Dummy module must be enabled in Kernel.
              C(gre) creates a gre interface.
              C(macvlan) creates a macvlan interface. C(macvlan_link) and C(macvlan_mode) are required.
              C(macvtap) creates a macvtap interface. C(macvtap_link) and C(macvtap_mode) are required.
              C(tuntap) creates a tuntap interface. C(tuntap_mode) is required.
              C(veth) creates two interfaces connect by one enlace. C(peer) is required.
              C(vlan) creates a vlan interface. C(vlan_link), C(vlan_id) and C(vlan_protocol) are required.
              C(vrf) creates a vrf interface. C(vrf_table) is required.
        choices: [ bridge, dummy, gre, macvlan, macvtap, tuntap, veth, vlan, vrf ]
        required: false
    macvlan_link:
        description:
            - The interface that new interface will use. It is required when C(type) is
              C(macvlan).
        required: false
    macvtap_link:
        description:
            - The interface that new interface will use. It is required when C(type) is
              C(macvtap).
        required: false
    vlan_link:
        description:
            - The interface that new interface will use. It is required when C(type) is
              C(vlan).
        required: false
    peer:
        description:
            - Name of peer interface when C(type) is C(veth). It is required when C(type) is C(veth).
        required: false
    mtu:
        description:
            - Change MTU on interface.
        required: false
    promiscuity:
        description:
            - Change promiscuity mode.
        required: false
        type: bool
    vlan_id:
        description:
            - Vlan ID number. Between 1 and 4095.
        required: false
    vlan_protocol:
        description:
            - Kind vlan protocol to use.
        required: false
        choices: [ 802.1q, 802.1ad ]
    macvlan_mode:
        description:
            - MacVLAN mode.
        required: false
        choices: [ vepa, private, bridge, passthru ]
    macvtap_mode:
        description:
            - MacVtap mode.
        required: false
        choices: [ vepa, private, bridge, passthru ]
    tuntap_mode:
        description:
            - TUNTAP mode.
        required: false
        choices: [ tun, tap ]
    vrf_table:
        description:
            - VRF table value. 1 <= vrf_table <= 4294967295
        required: false
    gre_local:
        description:
            - Local GRE address
        required: false
    gre_remote:
        description:
            - Remote GRE address
        required: false
    gre_ttl:
        description:
            - GRE Time to Live. 1 <= gre_ttl <= 255
        required: false
    gre_ikey:
        description:
            - ????
        required: false
    gre_okey:
        description:
            - ????
        required: false
    gre_iflag:
        description:
            - ????
        required: false
    gre_oflag:
        description:
            - ????
        required: false
    vxlan_link:
        description:
            - VXLAN source interface.
        required: false
    vxlan_id:
        description:
            - VXLAN Network Identifier (VNI). 0 <= vxlan_id <= 16777215
        required: false
        type: int
    vxlan_group:
        description:
            - VXLAN Multicast Group address.
        required: false
    vxlan_ttl:
        description:
            - VXLAN Time To Live. 1 <= vxlan_ttl <= 255
        required: false
requirements: [ pyroute2 ]
notes:
    - Online iproute2 Manpage
'''

EXAMPLES = '''

# This module can execute more than one network operation using a unique role.
# Create new veth interface, define ipv4 address and MTU (ip command):
# # ip link add dev veth0 type veth peer name veth1
# # ip link set dev veth0 mtu 1200
# # ip addr add dev veth0 192.168.100.1/24

- name: Create a veth interface, define ipv4 and MTU...
  ip:
    name: veth0
    link: present
    type: veth
    peer: veth1
    mtu: 1200
    addr: present
    ip: 192.168.100.1/24

# Set up a interface (ip command)
# # ip link set up dev veth0

- name: Set up veth0 interface...
  ip:
    name: veth0
    state: up

# Delete a interface (ip command)
# # ip link del dev veth0
# In this case, veth1 will be deleted too (veth interface must de exist in pair)

- name: Delete veth0 interface...
  ip:
    name: veth0
    link: absent

# Create a vlan interface
- name: Create vlan interface
  ip:
    name: vlan13
    link: present
    type: vlan
    vlan_id: 13
    vlan_protocol: 802.1q
'''

from ansible.module_utils.basic import AnsibleModule

try:
    from pyroute2 import IPDB, NetlinkError
    from pyroute2.ipdb.exceptions import CreateException, CommitException
    from pyroute2.netlink.rtnl.ifinfmsg import IFF_PROMISC
    HAS_PYROUTE2 = True
except:
    HAS_PYROUTE2 = False

GRE = ['gre_local', 'gre_remote', 'gre_ttl', 'gre_ikey', 'gre_okey', 'gre_iflag', 'gre_oflag']
MACVLAN = ['macvlan_link', 'macvlan_mode']
MACVTAP = ['macvtap_link', 'macvtap_mode']
TUNTAP = ['tuntap_mode']
VETH = ['peer']
VLAN = ['vlan_link', 'vlan_id', 'vlan_protocol']
VXLAN = ['vxlan_link', 'vxlan_id', 'vxlan_group', 'vxlan_ttl']
VRF = ['vrf_table']
OPTIONS = ['mtu', 'promiscuity', 'state']
MAIN = ['name', 'link', 'type']


def parse_params(module):
    if module.params.get('link') == 'present':
        if module.params.get('type') == 'bridge':
            valid_options = OPTIONS + MAIN
            if module.params.keys() not in valid_options:
                module.fail_json(msg='Only this options can be used: {0}'.format(valid_options))
        elif module.params.get('type') == 'dummy':
            valid_options = OPTIONS + MAIN
            if module.params.keys() not in valid_options:
                module.fail_json(msg='Only this options can be used: {0}'.format(valid_options))
        elif module.params.get('type') == 'gre':
            valid_options = OPTIONS + MAIN + GRE
            if module.params.keys() not in valid_options:
                module.fail_json(msg='Only this options can be used: {0}'.format(valid_options))
        elif module.params.get('type') == 'macvlan':
            valid_options = OPTIONS + MAIN + MACVLAN
            if module.params.keys() not in valid_options:
                module.fail_json(msg='Only this options can be used: {0}'.format(valid_options))
        elif module.params.get('type') == 'macvtap':
            valid_options = OPTIONS + MAIN + MACVTAP
            if module.params.keys() not in valid_options:
                module.fail_json(msg='Only this options can be used: {0}'.format(valid_options))
        elif module.params.get('type') == 'tuntap':
            valid_options = OPTIONS + MAIN + TUNTAP
            if module.params.keys() not in valid_options:
                module.fail_json(msg='Only this options can be used: {0}'.format(valid_options))
        elif module.params.get('type') == 'veth':
            valid_options = OPTIONS + MAIN + VETH
            if module.params.keys() not in valid_options:
                module.fail_json(msg='Only this options can be used: {0}'.format(valid_options))
        elif module.params.get('type') == 'vlan':
            valid_options = OPTIONS + MAIN + VLAN
            if module.params.keys() not in valid_options:
                module.fail_json(msg='Only this options can be used: {0}'.format(valid_options))
        elif module.params.get('type') == 'vxlan':
            valid_options = OPTIONS + MAIN + VXLAN
            if module.params.keys() not in valid_options:
                module.fail_json(msg='Only this options can be used: {0}'.format(valid_options))
        else:
            valid_options = OPTIONS + MAIN + VRF
            if module.params.keys() not in valid_options:
                module.fail_json(msg='Only this options can be used: {0}'.format(valid_options))
    elif module.params.get('link') == 'absent':
        if module.params.keys() not in ['name', 'link']:
            module.fail_json(msg='When absent link is used, you must not use any other options')
    else:
        # Link does not defined
        if module.params.keys() not in OPTIONS:
            module.fail_json(msg='When link is not used, you can choose only this options: {0}'.format(OPTIONS))


def main():
    argument_spec = {
        'name': {'required': True},
        'link': {'choices': ['present', 'absent', 'up', 'down'],
                 'required': False},
        'type': {'choices': ['bridge', 'dummy', 'gre', 'macvlan',
                             'macvtap', 'tuntap', 'veth',
                             'vlan', 'vrf', 'vxlan'],
                 'required': False},
        'vlan_link': {'required': False},
        'vlan_id': {'required': False,
                    'type': 'int'},
        'vlan_protocol': {'choices': ['802.1q', '802.1ad'],
                          'required': False},
        'macvlan_link': {'required': False},
        'macvlan_mode': {'choices': ['vepa', 'private', 'bridge', 'passthru'],
                         'required': False},
        'macvtap_link': {'required': False},
        'macvtap_mode': {'choices': ['vepa', 'private', 'bridge', 'passthru'],
                         'required': False},
        'tuntap_mode': {'choices': ['tun', 'tap'],
                        'required': False},
        'vrf_table': {'required': False,
                      'type': 'int'},
        'gre_local': {'required': False},
        'gre_remote': {'required': False},
        'gre_ttl': {'required': False,
                    'type': 'int'},
        'gre_ikey': {'required': False},
        'gre_okey': {'required': False},
        'gre_iflag': {'required': False},
        'gre_oflag': {'required': False},
        'vxlan_link': {'required': False},
        'vxlan_id': {'required': False,
                     'type': 'int'},
        'vxlan_group': {'required': False},
        'vxlan_ttl': {'required': False,
                      'type': 'int'},
        'link_interface': {'required': False},
        'peer': {'required': False},
        'mtu': {'type': 'int'},
        'promiscuity': {'type': 'bool'}
    }

    required_if = [['link', 'present', ['type']],
                   ['type', 'macvlan', ['macvlan_link', 'macvlan_mode']],
                   ['type', 'macvtap', ['macvtap_link', 'macvtap_mode']],
                   ['type', 'tuntap', ['tuntap_mode']],
                   ['type', 'veth', ['peer']],
                   ['type', 'vlan', ['vlan_id']],
                   ['type', 'vrf', ['vrf_table']]]

    module = AnsibleModule(argument_spec,
                           required_if=required_if,
                           supports_check_mode=True)
    if not HAS_PYROUTE2:
        module.fail_json(msg='pyroute2 required for this module')
    parse_params(module)

    ipdb = IPDB()
    if module.params.get('link') == 'present':
        # Verify if interface exists before try to create a new interface
        if ipdb.interfaces.get(module.params.get('name')):
            module.exit_json(changed=False, msg='Interface {0} already exists'.format(module.params.get('name')))

        if module.params.get('type') == 'bridge' or module.params.get('type') == 'dummy':
            ipdb.create(ifname=module.params.get('name'), kind=module.params.get('type')).commit()
        elif module.params.get('type') == 'gre':
            pass
        elif module.params.get('type') == 'macvlan':
            ipdb.create(ifname=module.params.get('name'),
                        kind='macvlan',
                        link=module.params.get('macvlan_link'),
                        macvlan_mode=module.params.get('macvlan_mode')).commit()
        elif module.params.get('type') == 'macvtap':
            ipdb.create(ifname=module.params.get('name'),
                        kind='macvtap',
                        link=module.params.get('macvtap_link'),
                        macvlan_mode=module.params.get('macvtap_mode')).commit()
        elif module.params.get('type') == 'tuntap':
            ipdb.create(ifname=module.params.get('name'),
                        kind='tuntap',
                        mode=module.params.get('tuntap_mode')).commit()
        elif module.params.get('type') == 'veth':
            ipdb.create(ifname=module.params.get('name'),
                        kind='veth',
                        peer=module.params.get('peer')).commit()
        elif module.params.get('type') == 'vlan':
            if module.params.get('vlan_id') < 0 or module.params.get('vlan_id') > 4095:
                module.fail_json(msg='0 <= vlan_id <= 4095')

            if module.params.get('vlan_protocol') == '802.1q' or not module.params.get('vlan_protocol'):
                ipdb.create(ifname=module.params.get('name'),
                            kind='vlan',
                            link=module.params.get('vlan_link'),
                            vlan_id=module.params.get('vlan_id'),
                            vlan_protocol=0x8100).commit()
            elif module.params.get('vlan_protocol') == '802.1ad':
                ipdb.create(ifname=module.params.get('name'),
                            kind='vlan',
                            link=module.params.get('vlan_link'),
                            vlan_id=module.params.get('vlan_id'),
                            vlan_protocol=0x88a8).commit()
        elif module.params.get('type') == 'vxlan':
            if module.params.get('vxlan_ttl') < 1 or module.params.get('vxlan_ttl') > 255:
                module.fail_json(msg='1 <= vxlan_ttl <= 255')
            if module.params.get('vxlan_id') < 0 or module.params.get('vxlan_id') > 16777215:
                module.fail_json(msg='0 <= vxlan_id <= 16777215')
            ipdb.create(ifname=module.params.get('name'),
                        kind='vxlan',
                        vxlan_link=module.params.get('vxlan_link'),
                        vxlan_id=module.params.get('vxlan_id'),
                        vxlan_group=module.params.get('vxlan_group'),
                        vxlan_ttl=module.params.get('vxlan_ttl'))
        else:
            if module.params.get('vrf_table') < 1 or module.params.get('vrf_table') > (2**32 - 1):
                module.fail_json(msg='1 <= vrf_table <= 4294967295(2**32 - 1)')
            # VRF manipulation support is present in iproute2 version 4.3.
            ipdb.create(ifname=module.params.get('name'),
                        kind='vrf',
                        vrf_table=module.params.get('vrf_table')).commit()
    elif module.params.get('link') == 'absent':
        # Verify if interface exists before try to remove
        if not ipdb.interfaces.get(module.params.get('name')):
            module.fail_json(msg='Interface {0} does not exists'.format(module.params.get('name')))
        try:
            with ipdb.interfaces[module.params.get('name')] as iface:
                iface.remove()
        except Exception as e:
            module.fail_json(msg='Error while remove interface: {0}'.format(e))
    else:
        pass

    # Verify if interface exists before try to change mtu, promiscuity and state
    if not ipdb.interfaces.get(module.params.get('name')):
        module.fail_json(msg='Interface {0} does not exists'.format(module.params.get('name')))

    if module.params.get('mtu'):
        with ipdb.interfaces[module.params.get('name')] as iface:
            iface.set('mtu', module.params.get('mtu'))
    if module.params.get('promiscuity'):
        with ipdb.interfaces[module.params.get('name')] as iface:
            iface['flags'] |= IFF_PROMISC
    if module.params.get('state'):
        with ipdb.interfaces[module.params.get('name')] as iface:
            if iface.operstate.down() == module.params.get('state'):
                module.exit_json(changed=False, msg='The {0} interface state '
                                                    'is already {1}'.format(module.params.get('name'),
                                                                            module.params.get('state')))
            else:
                if module.params.get('state') == 'up':
                    iface.up()
                else:
                    iface.down()
    module.exit_json(changed=True)


if __name__ == '__main__':
    main()
