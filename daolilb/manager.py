#!/usr/bin/env python

from ryu.lib import hub
#hub.patch(thread=False)
hub.patch(thread=True)

import logging
import sys

from oslo_config import cfg

from ryu import cfg as ryu_cfg
from ryu import log
log.early_init_log(logging.DEBUG)

from ryu.base.app_manager import AppManager

CONF = cfg.CONF
CONF.register_cli_opts([
    cfg.BoolOpt('enable-debugger', default=False,
                help='don\'t overwrite Python standard threading library'
                '(use only for debugging)'),
])

def main():
    args = sys.argv[1:]
    try:
        CONF(args=args, prog=sys.argv[0],
             project='daolicontroller', version='1.1',
             default_config_files=['/etc/daolicontroller/daolicontroller.conf'])
    except cfg.ConfigFilesNotFoundError:
        CONF(args=args, prog=sys.argv[0],
             project='daolicontroller', version='1.1')

    log.init_log()

    #if ryu_cfg.CONF is not CONF:
    #    ryu_cfg.CONF(args=args, project='ryu')

    #if CONF.enable_debugger:
    #    LOG = logging.getLogger('daolicontroller')
    #    msg = 'debugging is available (--enable-debugger option is turned on)'
    #    LOG.info(msg)
    #else:
    	#hub.patch(thread=True)

    AppManager.run_apps(['daolicontroller.ofa_agent'])

main()
