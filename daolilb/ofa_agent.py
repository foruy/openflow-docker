import logging
import os
import struct
from webob import Response

from eventlet import greenthread
from requests.exceptions import ConnectionError

from ryu import cfg
from ryu.app.wsgi import route
from ryu.app.wsgi import ControllerBase, WSGIApplication
from ryu.base import app_manager
from ryu.controller import dpset
from ryu.controller import handler
from ryu.controller.handler import set_ev_cls
from ryu.controller import ofp_event
from ryu.lib import dpid as dpid_lib
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import icmp
from ryu.lib.packet import ethernet
from ryu.lib.packet import packet
from ryu.ofproto import inet
from ryu.ofproto import ofproto_v1_0 as ryu_ofp10
from ryu.ofproto import ofproto_v1_2 as ryu_ofp12
from ryu.ofproto import ofproto_v1_3 as ryu_ofp13

from daolicontroller.client import DockerHTTPClient
from daolicontroller.db import DBase
from daolicontroller import exceptions
from daolicontroller.lib import PacketARP, PacketIPv4
from daolicontroller.objects import PortState
from daolicontroller.objects import Container

try:
    import json
except ImportError:
    import simplejson as json

CONF = cfg.CONF

CONF.register_opts([
    cfg.StrOpt('api_url', default='http://127.0.0.1:3376',
               help='daolinet api url'),
])

LOG = logging.getLogger(__name__)

class GroupController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(GroupController, self).__init__(req, link, data, **config)
        self.app = data['app']

    @route('policy', '/v1/policy', methods=['POST'])
    def delete(self, _req, **kwargs):
        body = json.loads(_req.body)

        if not body.has_key('sid') or not body.has_key('did'):
            return Response(status=400)

        self.app.flow_delete(body['sid'], body['did'])
        return Response(status=200)

class OFAgentRyuApp(app_manager.RyuApp):
    OFP_VERSIONS = [ryu_ofp12.OFP_VERSION]
    _CONTEXTS = {'dpset': dpset.DPSet,
                 'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(OFAgentRyuApp, self).__init__(*args, **kwargs)
        self.port_state = {}
        self.dps = kwargs['dpset'].dps
        self.waiters = {}
        self.packetlib = PacketLib(self)
        kwargs['wsgi'].register(GroupController, {'app': self.packetlib})

    @handler.set_ev_cls(dpset.EventDP)
    def dp_hadler(self, ev):
        dpid = ev.dp.id
        if ev.enter:
            if dpid not in self.port_state:
                self.port_state[dpid] = PortState()
                for port in ev.ports:
                    self.port_state[dpid].add(port)
            self.packetlib.init_flow(ev.dp)
        else:
            if dpid in self.port_state:
                for port in self.port_state[dpid].values():
                    self.port_state[dpid].remove(port)
                del self.port_state[dpid]

    @handler.set_ev_cls(dpset.EventPortAdd)
    def port_add_handler(self, ev):
        self.port_state[ev.dp.id].add(ev.port)

    @handler.set_ev_cls(dpset.EventPortDelete)
    def port_del_handler(self, ev):
        self.port_state[ev.dp.id].remove(ev.port)

    @handler.set_ev_cls(dpset.EventPortModify)
    def port_mod_handler(self, ev):
        self.port_state[ev.dp.id].add(ev.port)

    @set_ev_cls([ofp_event.EventOFPStatsReply,
                 ofp_event.EventOFPFlowStatsReply,
                 ofp_event.EventOFPAggregateStatsReply,
                ], handler.MAIN_DISPATCHER)
    def stats_reply_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath

        if dp.id not in self.waiters:
            return
        if msg.xid not in self.waiters[dp.id]:
            return
        lock, msgs = self.waiters[dp.id][msg.xid]
        msgs.append(msg)

        flags = 0
        if dp.ofproto.OFP_VERSION == ryu_ofp10.OFP_VERSION:
            flags = dp.ofproto.OFPSF_REPLY_MORE
        elif dp.ofproto.OFP_VERSION == ryu_ofp12.OFP_VERSION:
            flags = dp.ofproto.OFPSF_REPLY_MORE
        elif dp.ofproto.OFP_VERSION == ryu_ofp13.OFP_VERSION: 
            flags = dp.ofproto.OFPMPF_REPLY_MORE

        if msg.flags & flags:
            return
        del self.waiters[dp.id][msg.xid]
        lock.set()

    #@set_ev_cls(ofp_event.EventOFPSwitchFeatures, handler.CONFIG_DISPATCHER)
    #def _switch_features_handler(self, ev):
    #    self.packetlib.switch_features_handler(ev)

    @set_ev_cls(ofp_event.EventOFPPacketIn, handler.MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        #try:
            self.packetlib.packet_in_handler(ev)
        #except ConnectionError:
        #    LOG.warn("Connection aborted. Retring again.")
        #    greenthread.sleep(2)

class PacketLib(DBase):

    def __init__(self, ryuapp):
        super(PacketLib, self).__init__()
        self.gateway = self.db.gateways()
        self.container = Container()
        self.client = DockerHTTPClient(self, CONF.api_url)
	self.client.container_list()
        self.arp = PacketARP(self, ryuapp)
        self.ipv4 = PacketIPv4(self, ryuapp)

    def gateway_get(self, dpid):
        normal_dpid = dpid_lib.dpid_to_str(dpid)
        gateway = self.gateway.get(normal_dpid)
        if not gateway:
            try:
                gateway = self.db.gateway(normal_dpid)[normal_dpid]
            except:
                LOG.warn("Datapath[%s] could not be found." % normal_dpid)

        return gateway

    def packet_in_handler(self, ev):
        """Check a packet-in message.

           Build and output a packet-out.
        """
        msg = ev.msg
        datapath = msg.datapath
        port = msg.match['in_port']

        gateway = self.gateway_get(datapath.id)
        if gateway is None:
            return

        pkt = packet.Packet(msg.data)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)

        if not pkt_ethernet:
            LOG.info("drop non-ethernet packet")
            return

        pkt_arp = pkt.get_protocol(arp.arp)
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)

        if pkt_arp:
            if pkt_arp.opcode == arp.ARP_REQUEST:
                self.arp.run(msg, pkt_ethernet, pkt_arp, gateway)
        elif pkt_ipv4:
            pkt_tp = pkt.get_protocol(tcp.tcp) or \
                     pkt.get_protocol(udp.udp) or \
                     pkt.get_protocol(icmp.icmp)

            LOG.debug("packet-in msg %s %s %s from %s", 
                      datapath.id, pkt_ipv4, pkt_tp, port)
	    print port, pkt_arp, pkt_ipv4, pkt_tp
            if pkt_tp and port and (gateway['IntDev'] != gateway['ExtDev']):
		try:
                	self.ipv4.run(msg, pkt_ethernet, pkt_ipv4, pkt_tp, gateway)
		except exceptions.DevicePortNotFound:
			LOG.warn(e.message)
		except exceptions.KeyNotFound:
			pass

    def init_flow(self, dp):
        gateway = self.gateway_get(dp.id)
        if gateway is not None:
            self.arp.init_flow(dp, gateway)
            self.ipv4.init_flow(dp, gateway)

    def flow_delete(self, sid, did):
        self.ipv4.flow_delete(sid, did)
