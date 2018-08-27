# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


# Load balancer, OpenFlow v1.0


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp


class Server:

    mac = None
    ip = None
    port = None

    def __init__(self, mac, ip, port):
        self.mac = mac
        self.ip = ip
        self.port = port


class Network:

    lb_mac = None
    lb_ip = None

    servers = []
    servers_num = None

    def __init__(self):
        self.lb_mac = '00:00:00:00:aa:0a'
        self.lb_ip = '10.8.10.99'

        self.big_servers_chosen = False

        if self.big_servers_chosen:

            # big servers
            self.servers = [
                Server("90:1b:0e:48:f2:7b", self.lb_ip, 1),
                Server("90:1b:0e:05:9c:67", self.lb_ip, 3),
                Server("90:1b:0e:48:f1:97", self.lb_ip, 5)
            ]


        else:

            # pi servers
            self.servers = [
                Server("b8:27:eb:d5:72:15", self.lb_ip, 1),
                Server("b8:27:eb:a4:71:a1", self.lb_ip, 3),
                Server("b8:27:eb:02:ea:80", self.lb_ip, 5)
            ]

        self.servers_num = len(self.servers)


class LoadBalancingApp(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    msg = None       # Message of the event -> ryu.controller.ofp_event.EventOFPMsgBase.msg
    dp = None        # Datapath of the message -> ryu.controller.controller.Datapath()

    def __init__(self, *args, **kwargs):
        super(LoadBalancingApp, self).__init__(*args, **kwargs)

        self.net = Network()    # network configuration
        self.ip_to_mac = {}     # contains ip to mac of clients
        self.rr_counter = 0     # chooses which server to be accessed, round robin

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        self.msg = ev.msg
        self.dp = self.msg.datapath
        self.set_default_flows()

    def set_default_flows(self):
        # Drop_IPv6
        match = self.dp.ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IPV6)
        self.add_flow(match, None, 0)

    def add_flow(self, match, actions, idle_timeout=0, priority=0):
        ofproto = self.dp.ofproto
        priority = self.dp.ofproto.OFP_DEFAULT_PRIORITY if priority == 0 else priority
        mod = self.dp.ofproto_parser.OFPFlowMod(datapath=self.dp, match=match, cookie=0,
                                                command=ofproto.OFPFC_ADD, idle_timeout=idle_timeout,
                                                hard_timeout=0, priority=priority,
                                                flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        self.dp.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):   # When a Packet arrives at controller, this function is called

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        ar = pkt.get_protocol(arp.arp)
        ip = pkt.get_protocol(ipv4.ipv4)
        pkt_icmp = pkt.get_protocol(icmp.icmp)
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        src = eth.src

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:  # todo: Ignore LLDP packet, shall be in the flow table to drop?
            return

        if eth.ethertype == ether_types.ETH_TYPE_ARP:  # Resolve ARP Requests

            if ar.dst_ip == self.net.lb_ip:     # Is request to the lb?

                p = packet.Packet()
                p.add_protocol(ethernet.ethernet(dst=src, src=self.net.lb_mac, ethertype=ether_types.ETH_TYPE_ARP))
                p.add_protocol(arp.arp(hwtype=1, proto=0x800, hlen=6, plen=4, opcode=2,
                                       src_mac=self.net.lb_mac, src_ip=self.net.lb_ip, dst_mac=src, dst_ip=ar.src_ip))

            else:   # If request is not to gw and from servers (e.g. local clients), then use lookup table

                # Remarks on ARP to gateway:
                # Basically, Gateway MAC has been learned for outside clients;
                # therefore, NO NEED TO PROCESS ARP TO GW

                # If request not from servers or request not in table, ignore packet
                if msg.in_port not in [s.port for s in self.net.servers] or ar.dst_ip not in self.ip_to_mac:
                    return

                macc = self.ip_to_mac[ar.dst_ip]
                p = packet.Packet()
                p.add_protocol(ethernet.ethernet(dst=src, src=macc, ethertype=ether_types.ETH_TYPE_ARP))
                p.add_protocol(arp.arp(hwtype=1, proto=0x800, hlen=6, plen=4, opcode=2,
                                       src_mac=macc, src_ip=ar.dst_ip, dst_mac=src, dst_ip=ar.src_ip))

            out_port = ofproto.OFPP_IN_PORT
            self.send_packet(p, msg, datapath, out_port)

        elif ip is not None:    # Resolve IP

            if ip.proto == 0x01:    # Resolve ICMP

                if pkt_icmp.type != icmp.ICMP_ECHO_REQUEST and ip.dst != self.net.lb_ip:    # answer ping requests to lb
                    return

                p = packet.Packet()
                p.add_protocol(ethernet.ethernet(dst=src, src=self.net.lb_mac, ethertype=ether_types.ETH_TYPE_IP))
                p.add_protocol(ipv4.ipv4(dst=ip.src, src=self.net.lb_ip, proto=0x01))
                p.add_protocol(icmp.icmp(type_=icmp.ICMP_ECHO_REPLY, code=icmp.ICMP_ECHO_REPLY_CODE, csum=0,
                                         data=pkt_icmp.data))
                out_port = ofproto.OFPP_IN_PORT
                self.send_packet(p, msg, datapath, out_port)

            elif ip.proto == 0x06: # Resolve TCP

                if pkt_tcp.src_port == 80: # Ignore packets from server when creating rule
                    return

                ip_src = ip.src

                # if ip of client has been learned (flow installed), no need to process
                # helps with burst of traffic that creates duplicate flows
                if ip_src in self.ip_to_mac:
                    return

                out_port = self.net.servers[self.rr_counter].port
                mac_dest = self.net.servers[self.rr_counter].mac


                ip.dst = self.net.lb_ip

                # Forward Received TCP Packet to the selected Server
                p = packet.Packet()
                p.add_protocol(ethernet.ethernet(dst=mac_dest, src=src, ethertype=ether_types.ETH_TYPE_IP))
                p.add_protocol(ip)
                p.add_protocol(pkt_tcp)

                self.send_packet(p, msg, datapath, out_port)

                # Add Flow Entry
                match = datapath.ofproto_parser.OFPMatch(in_port=msg.in_port, dl_type=0x0800,
                                                         nw_proto=0x06, nw_src=ip_src, nw_dst=self.net.lb_ip)
                actions = [parser.OFPActionSetDlDst(mac_dest), parser.OFPActionOutput(out_port)]
                self.add_flow(match, actions)

                # Insert reverse flow
                match = datapath.ofproto_parser.OFPMatch(in_port=out_port, dl_type=0x0800,
                                                         nw_proto=0x06, nw_src=self.net.lb_ip, nw_dst=ip_src)
                actions = [parser.OFPActionSetDlSrc(self.net.lb_mac), parser.OFPActionOutput(msg.in_port)]
                self.add_flow(match, actions)

                # Update ARP table
                self.ip_to_mac.update({ip_src: src})

                # Update RR counter
                self.rr_counter = (self.rr_counter + 1) % self.net.servers_num

    # Send Packet
    @staticmethod
    def send_packet(p, msg, datapath, out_port):
        p.serialize()
        data = p.data
        msg.buffer_id = 0xffffffff      # used switch HP 2920 does not support Packet In buffering, hence buffer_id = -1
        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
                                                   actions=actions, data=data)
        datapath.send_msg(out)