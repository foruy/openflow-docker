import logging

from ryu import cfg
from ryu.lib import dpid as dpid_lib
from ryu.ofproto import ether
from ryu.ofproto import inet

from daolicontroller import exception
from daolicontroller import utils
from daolicontroller.lib.base import PacketBase
from daolicontroller.lib.constants import CONNECTED, DISCONNECTED

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

class PacketTCP(PacketBase):
    priority = 10

    def _redirect(self, dp, pkt_tp, inport, outport, **kwargs):
	kwargs['eth_type'] = ether.ETH_TYPE_IP
	kwargs['ip_proto'] = inet.IPPROTO_TCP
	kwargs['tcp_src'] = pkt_tp.src_port
	kwargs['tcp_dst'] = pkt_tp.dst_port
	super(PacketTCP, self)._redirect(dp, inport, outport, **kwargs)

    def run(self, msg, pkt_ether, pkt_ipv4, pkt_tp, src_gateway, container, **kwargs):
        dp = msg.datapath
        in_port = msg.match['in_port']

	dpid = dpid_lib.str_to_dpid(container['DataPath'])
	dst_gateway = self.manager.gateway_get(dpid)
	if not dst_gateway:
		return False

	cdp = self.ryuapp.dps.get(dpid)
	if not cdp:
		return False

	self.container_flow(dp, cdp, pkt_ipv4, pkt_tp,
			    src_gateway, dst_gateway, container)
	self.gateway_flow(msg, cdp, pkt_ether, pkt_ipv4, pkt_tp,
		          src_gateway, dst_gateway)

    def gateway_flow(self, msg, cdp, pkt_ether, pkt_ipv4, pkt_tp, src_gateway,
		     dst_gateway):
        dp = msg.datapath
        ofp, ofp_parser, ofp_set, ofp_out = self.ofp_get(dp)

	src_gwport = self.port_get(dp, src_gateway['IntDev'])
	dst_gwport = self.port_get(cdp, dst_gateway['IntDev'])

        in_port = msg.match['in_port']
	input_match = ofp_parser.OFPMatch(
		in_port=in_port,
		eth_type=ether.ETH_TYPE_IP,
		ip_proto=pkt_ipv4.proto,
		ipv4_src=pkt_ipv4.src,
		ipv4_dst=pkt_ipv4.dst,
		tcp_src=pkt_tp.src_port,
		tcp_dst=pkt_tp.dst_port,
	)
	input_action = [
		ofp_set(eth_src=src_gwport.hw_addr),
		ofp_set(eth_dst=dst_gwport.hw_addr),
		ofp_set(ipv4_dst=dst_gateway['IntIP']),
		ofp_out(src_gwport.port_no)
	]

	output_match = ofp_parser.OFPMatch(
		in_port=src_gwport.port_no,
		eth_type=ether.ETH_TYPE_IP,
		ip_proto=pkt_ipv4.proto,
		ipv4_src=dst_gateway['IntIP'],
		ipv4_dst=pkt_ipv4.src,
		tcp_src=pkt_tp.dst_port,
		tcp_dst=pkt_tp.src_port,
	)
	output_action = [
		ofp_set(eth_src=pkt_ether.dst),
		ofp_set(eth_dst=pkt_ether.src),
		ofp_set(ipv4_src=pkt_ipv4.dst),
		ofp_set(ipv4_dst=pkt_ipv4.src),
		ofp_out(in_port)
	]

	self.add_flow(dp, input_match, input_action)
	self.add_flow(dp, output_match, output_action)
	self.packet_out(msg, dp, input_action)

    def container_flow(self, dp, cdp, pkt_ipv4, pkt_tp, src_gateway,
		       dst_gateway, container):
        ofp, ofp_parser, ofp_set, ofp_out = self.ofp_get(cdp)

	src_gwport = self.port_get(dp, src_gateway['IntDev'])
	dst_gwport = self.port_get(cdp, dst_gateway['IntDev'])
	gwport = self.port_get(cdp, id=container['NetworkId'])
	cport = self.port_get(cdp, id=container['EndpointID'])

	input_match = ofp_parser.OFPMatch(
		in_port=dst_gwport.port_no,
		eth_type=ether.ETH_TYPE_IP,
		ip_proto=pkt_ipv4.proto,
		ipv4_src=pkt_ipv4.src,
		ipv4_dst=dst_gateway['IntIP'],
		tcp_src=pkt_tp.src_port,
		tcp_dst=pkt_tp.dst_port,
	)
	input_action = [
		ofp_set(eth_src=gwport.hw_addr),
		ofp_set(eth_dst=container['MacAddress']),
		ofp_set(ipv4_dst=container['IPv4Address']),
		ofp_out(cport.port_no),
	]

	output_match = ofp_parser.OFPMatch(
		in_port=cport.port_no,
		eth_type=ether.ETH_TYPE_IP,
		ip_proto=pkt_ipv4.proto,
		ipv4_src=container['IPv4Address'],
		ipv4_dst=pkt_ipv4.src,
		tcp_src=pkt_tp.dst_port,
		tcp_dst=pkt_tp.src_port,
	)
	output_action = [
		ofp_set(eth_src=dst_gwport.hw_addr),
		ofp_set(eth_dst=src_gwport.hw_addr),
		ofp_set(ipv4_src=dst_gateway['IntIP']),
		ofp_out(dst_gwport.port_no)
	]

	self.add_flow(cdp, input_match, input_action)
	self.add_flow(cdp, output_match, output_action)
