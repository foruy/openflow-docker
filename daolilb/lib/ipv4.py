import collections
import logging
from threading import Timer

from ryu import cfg
from ryu.lib import dpid as dpid_lib
from ryu.lib import ofctl_v1_0
from ryu.lib import ofctl_v1_2
from ryu.lib import ofctl_v1_3
from ryu.lib.packet.ipv4 import ipv4
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.ofproto import inet

from daolicontroller import exceptions
from daolicontroller import utils
from daolicontroller.lib.base import PacketBase
from daolicontroller.lib.constants import CONNECTED, DISCONNECTED

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

# supported ofctl versions
supported_ofctl = {
    ofproto_v1_0.OFP_VERSION: ofctl_v1_0,
    ofproto_v1_2.OFP_VERSION: ofctl_v1_2,
    ofproto_v1_3.OFP_VERSION: ofctl_v1_3,
}

DEFAULT_GAP = 4
INFILTER = [68, 2375, 4001, 6633]
OUTFILTER = [68, 2375, 4001, 6633]

class PacketIPv4(PacketBase):
    priority = 10

    def __init__(self, *args):
	self.register_protocol(*args)
        Timer(DEFAULT_GAP, self.monitor).start()
	super(PacketIPv4, self).__init__(*args)

    def register_protocol(self, *args):
	for p, clz in ipv4._TYPES.iteritems():
            pname = clz.__name__
            try:
                class_str = 'daolicontroller.lib.%s.Packet%s' % (
                        pname, pname.upper())
		obj = utils.import_class(class_str)
		setattr(self, pname, obj(*args))
	    except:
		pass

    def get_container(self, gateways, image):
        dp_dict = collections.defaultdict(list)
        containers = self.manager.client.container_list(image=image)
        for c in containers:
            dp_dict[c['DataPath']].append(c)

        return len(containers), dp_dict

    def monitor(self):
        for service in self.manager.db.services():
            self.callback(service)

        Timer(service['gap'], self.monitor).start()

    def callback(self, service):
        count = 0
        avail_gateways = []
        flow = {"match": {"dl_type": ether.ETH_TYPE_IP,
                          "ip_proto": inet.IPPROTO_TCP,
                          "tp_dst": service["gateway_port"]}}
        for gateway in self.manager.db.gateways().values():
            if gateway['IntDev'] == gateway['ExtDev']:
                avail_gateways.append(gateway)
                continue

            dpid = dpid_lib.str_to_dpid(gateway['DatapathID'])
            dp = self.ryuapp.dps.get(dpid)
            if not dp:
                continue

            _ofctl = supported_ofctl.get(dp.ofproto.OFP_VERSION, None)
            if _ofctl is not None:
                flows = _ofctl.get_aggregate_flow_stats(dp, self.ryuapp.waiters, flow)
                print flow, flows
                if flows[str(dp.id)]:
                    count += sum([f['flow_count'] for f in flows[str(dp.id)]])

        print 'COUNT:',count
        div = count / service["threshold"]
        if div > 0:
            div = count / (service["threshold"] + div)

        image = service["service_image"]
        clen, dp_dict = self.get_container(avail_gateways, image)

        print 'DIV:LEN=%d:%d' % (div, clen)
        if div > clen:
            print 'Create Container'
            self.client.create_container(image)
        elif (clen - 1) > 0 and div < (clen - 1):
            dp = max(dp_dict, key=lambda x:len(dp_dict[x]))
            c = dp_dict[dp].pop()
            print 'Remove Container',  c["Name"]
            self.client.remove_container(c["Id"], force=True)

    def _redirect(self, dp, inport, outport, **kwargs):
        kwargs['eth_type'] = ether.ETH_TYPE_IP
        super(PacketIPv4, self)._redirect(dp, inport, outport, **kwargs)

    def init_flow(self, dp, gateway):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                          ofp.OFPCML_NO_BUFFER)]
        if gateway['IntDev'] != gateway['ExtDev']:
            ext_port = self.port_get(dp, gateway['ExtDev'])

            self._redirect(dp, ofp.OFPP_LOCAL, ext_port.port_no,
                           ipv4_src=gateway['ExtIP'])
            self._redirect(dp, ext_port.port_no, ofp.OFPP_LOCAL,
                           ip_proto=inet.IPPROTO_ICMP, ipv4_dst=gateway['ExtIP'])

            match = parser.OFPMatch(
                    in_port=ext_port.port_no,
                    eth_type=ether.ETH_TYPE_IP,
                    ipv4_dst=gateway['ExtIP'])

            self.add_flow(dp, match, actions, timeout=0, priority=1)

            match = parser.OFPMatch(in_port=ext_port.port_no)
	    self.add_flow(dp, match, actions=[], timeout=0, priority=1)

        int_port = self.port_get(dp, gateway['IntDev'])

        # Add flow where is from local host.
        self._redirect(dp, dp.ofproto.OFPP_LOCAL, int_port.port_no,
                       ipv4_src=gateway['IntIP'])

        # Add icmp flow coming from outer.
        self._redirect(dp, int_port.port_no, dp.ofproto.OFPP_LOCAL,
                       ip_proto=inet.IPPROTO_ICMP, ipv4_dst=gateway['IntIP'])

        match = parser.OFPMatch(
                in_port=int_port.port_no,
                eth_type=ether.ETH_TYPE_IP,
                ipv4_dst=gateway['IntIP'])

        self.add_flow(dp, match, actions, timeout=0, priority=1)

        match = parser.OFPMatch(in_port=int_port.port_no)
	self.add_flow(dp, match, actions=[], timeout=0, priority=1)

        # Add initial port flow. eg: docker socket port, etcd port.
        for port in INFILTER:
            self._redirect(dp, int_port.port_no, dp.ofproto.OFPP_LOCAL,
                           ip_proto=inet.IPPROTO_TCP, ipv4_dst=gateway['IntIP'],
                           tcp_dst=port)

        for port in OUTFILTER:
            self._redirect(dp, int_port.port_no, dp.ofproto.OFPP_LOCAL,
                           ip_proto=inet.IPPROTO_TCP, ipv4_dst=gateway['IntIP'],
                           tcp_src=port)

    def run(self, msg, pkt_ether, pkt_ipv4, pkt_tp, gateway, **kwargs):
        dp = msg.datapath
        in_port = msg.match['in_port']

	gw_port = self.port_get(dp, gateway['ExtDev'])

	if gw_port.port_no != in_port or pkt_ipv4.dst != gateway['ExtIP']:
		return False

	if pkt_ipv4.proto == inet.IPPROTO_ICMP:
		return False

	try:
		service = self.manager.db.service_get(pkt_tp.dst_port)
	except exceptions.KeyNotFound:
		kwargs = {'ipv4_src': pkt_ipv4.src, 'ipv4_dst': pkt_ipv4.dst}

		if hasattr(self, pkt_tp.protocol_name):
			getattr(self, pkt_tp.protocol_name)._redirect(
				dp, pkt_tp, in_port, dp.ofproto.OFPP_LOCAL,
				**kwargs)
		return True

	containers = self.manager.client.container_list(
			image=service['service_image'])

	if len(containers) <= 0:
		return False

        #if 

	index = utils.get_long_ip(pkt_ipv4.src) % len(containers)
	if hasattr(self, pkt_tp.protocol_name):
		getattr(self, pkt_tp.protocol_name).run(
			msg, pkt_ether, pkt_ipv4, pkt_tp, gateway,
			containers[index], **kwargs)
