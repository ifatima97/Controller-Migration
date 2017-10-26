from xml.etree import ElementTree as ET
from countrycode import getcountrycode
from climigration.climlogging import get_climlogger
import pandas as pd
import re

class Climigration():
    def __init__ (self, clixml, clixml_migrated):
               
        self.clixml = clixml
        self.clixml_migrated = clixml_migrated                  
        xf = open(self.clixml, 'r')                                   
        self.xmltree = ET.parse(self.clixml) 
        self.xmlroot = self.xmltree.getroot()        
        self.xmltree.write(self.clixml_migrated) 
        self.climlogger = get_climlogger()      

        self.parent_map = dict((c, p) for p in self.xmltree.getiterator() for c in p)       
                    
        #Skip Commands  List      
        self.rootlevel_skipcommands = [{'context': 'rootlevelcommand', 'command': 'healthpoll'}, # healthpoll disable to enable  
                                       {'context': 'rootlevelcommand', 'command': 'lanset'}]
           
        self.apcontext_skipcommands = [{'context': 'ap:<serial>', 'command': 'ipmcast-assembly'},
                                       {'context': 'ap:<serial>', 'command': 'bcast_disassoc'},#bcast_disassoc to no bcast_disassoc
                                       {'context': 'ap:<serial>', 'command': 'lldp'}, # no lldp to ap:<seria>: lldp <default announcement interval> <default Announcement Delay>
                                       {'context': 'ap:<serial>', 'command': 'poll_timeout'}, # poll_timeout value to default value
                                       {'context': 'ap:<serial>', 'command': 'aclist'}, # ????
                                       {'context': 'ap:<serial>:radio1', 'command': 'max-distance'},
                                       {'context': 'ap:<serial>:radio2', 'command': 'max-distance'},
                                       {'context': 'ap:<serial>:radio1', 'command': 'antsel'},
                                       {'context': 'ap:<serial>:radio2', 'command': 'antsel'},
                                       {'context': 'ap:<serial>:radio1', 'command': 'beaconp'},
                                       {'context': 'ap:<serial>:radio2', 'command': 'beaconp'},
                                       {'context': 'ap:<serial>:radio1', 'command': 'n_pmode'},
                                       {'context': 'ap:<serial>:radio2', 'command': 'pmode'},
                                       {'context': 'ap:<serial>:radio2', 'command': 'n_aggr_msdu'},
                                       {'context': 'ap:<serial>:radio2', 'command': 'n_addba_support'},
                                       {'context': 'ap:<serial>:radio1:dcs', 'command': 'mode'},
                                       {'context': 'ap:<serial>:radio2:dcs', 'command': 'event-type'}]
        
        self.availabilitycontext_skipcommands = [{'context': 'availability', 'command': 'fast_failover'},# no fast_failover to fast failover
                                                 {'context': 'availability', 'command': 'sync-mu'}] # no synch-mu to sync mu
        
        self.wlancontext_skipcommands = [{'context': 'wlans:<wlanservname>:qos-policy', 'command':'priority-map'},
                                         {'context': 'wlans:<wlanservname>:qos-policy', 'command': 'priority-override'}]
        
        self.rolecontext_skipcommands = [{'context': 'role:<rolename>', 'command' : 'traffic-mirror'},
                                         {'context': 'role:<rolename>', 'command' : 'egress-vlans'},
                                         {'context': 'role:<rolename>', 'command' : 'filter-status'},
                                         {'context': 'role:<rolename>', 'command' : 'ulfilterap'}]
        
        self.vnsmodecontext_skipcommands = [{'context': 'vnsmode:adminctr', 'command': 'rule-redirect'}] 
        
        self.mobilitycontext_skipcommands = [{'context': 'mobility', 'command': 'mrole'}]
            
        #Change Commands List
        self.wlancontext_changecommands = [{'context': 'wlans:<wlanservname>:priv',
                                            'command': 'mode', 
                                            'fromto': ['wep', 'none'], 
                                            'condition': None},
                                           {'context': 'wlans:<wlanservname>:priv',
                                            'command': 'mode', 
                                            'fromto': ['dwep', 'none'],
                                            'condition': None},
                                           {'context': 'wlans:<wlanservname>:priv',
                                            'command': 'mode',
                                             'fromto': ['wpa-v1', 'wpa-v2 auto'],
                                             'condition': None}]
        
        self.rolecontext_changecommands = [{'context': 'role:<rolename>',
                                            'command': 'access-control', 
                                            'fromto': ['no-change', 'deny'],
                                            'condition': None,
                                            'Warning': 'WarningText'},
                                           {'context': 'role:<rolename>',
                                            'command': 'default-cos', 
                                            'fromto': ['no-change', '"No-CoS"'],
                                            'condition': None},
                                           {'context': 'role:<rolename>',
                                            'command': 'access-control',
                                            'fromto': ['contain2vlan', 'deny'],
                                            'condition': True, 
                                            'concheckfxn': 'check_topology',
                                            'Warning': 'WarningText'}]
        
        #Remove Contexts Lists
        self.wlancontext_removecontexts = [{'context': 'wlans', 
                                            'condition': True, 
                                            'concheckfxn': 'check_wlanmode'}, #['mode', 'remote']
                                           {'context': 'wlans', 
                                            'condition': True, 
                                            'concheckfxn': 'check_wlanmode'}, #['mode', '3pap']
                                           {'context': 'wlans', 
                                            'condition': True, 
                                            'concheckfxn': 'check_wlanmode'}, #['mode', 'wds']
                                           {'context': 'wlans:<wlanservicename>:auth:captiveportal', 
                                            'condition': None}]
      
        self.apcontext_removecontexts = [{'context': 'ap:load-groups', 'condition': None}]
        
        self.vnscontext_removecontexts = [{'context': 'vnsmode:netflow-mirror', 'condition': None },
                                          {'context': 'vnsmode:radius', 'condition': None }] 

        self.topologyecontext_removecontexts = [{'context': 'topology:<topologyname>:l3:exceptions', 
                                                 'condition': None}]
        
        self.concheck_dispatcher = {'check_wlanmode': self.check_wlanmode, 
                                    'check_topology': self.check_topology_role}  
	
    def healthpoll_enable(self):
        #print self.healthpoll_enable.__name__
        '''Non configurables: health poll is always enabled'''
        rootlevel_commands = self.xmlroot.findall("./rootlevelcommand")        
        for rlc in rootlevel_commands:
            if rlc.text == 'healthpoll disable':
                rlc.text = 'healthpoll enable'
                self.climlogger.info('healthpoll: healthpoll is enabled\n')
                self.xmltree.write(self.clixml_migrated)
				
    def remove_unsupported_aps(self):
		supported_ap_list = ['3912ROW', '3916ROW', '3935ROW', '3965ROW', 'ap3801', 'ap3805ROW', 'ap38xx', 'ap3935IL']
		ap_commands0 = self.xmlroot.findall("./context0[@name='ap']/context1[@name='defaults']/context2")
		ap_commands1 = self.xmlroot.findall("./context0[@name='ap']/command")
		
		for command0 in ap_commands0:
			ap_found = 'false'
			for ap_index in range(len(supported_ap_list)):
				if command0.get('name') == supported_ap_list[ap_index]:
					ap_found = 'true'
			if ap_found == 'false':
				self.parent_map[command0].remove(command0)		
			
		for command1 in ap_commands1:
			if "serial import" in command1.text:
				if '37' in command1.text.split('"')[2]:
					self.parent_map[command1].remove(command1)
					ap_name = command1.text.split(' ')[2]
					ap_name_context1 = self.xmlroot.findall("./context0[@name='ap']/context1[@name='%s']" % ap_name)
					self.parent_map[ap_name_context1[0]].remove(ap_name_context1[0])
				
    def remove_unsupported_ports(self):
		#10.49.31.125 only supports esa0 and esa1 and Extreme-Corp; remove topology and role dependencies too
		l2ports_commands = self.xmlroot.findall("./context0[@name='l2ports']/context1")
		for command in l2ports_commands:
			if ((command.get('name') != 'esa0') and (command.get('name') != 'esa1') and (command.get('name') != 'Extreme-Corp')):
				port_name = command.get('name')
				self.parent_map[command].remove(command)
		        #self.climlogger.info('l2ports: deleted %s \n' % command.get('name'))
                
                topology_commands0 = self.xmlroot.findall("./context0[@name='topology']/command")
                for command in topology_commands0:
                    if command.text.split(' ')[0]=='create' and command.text.split(' ')[4]=='port':
                        if (not ('esa0' in command.text) and not ('esa1' in command.text) and not ('Extreme-Corp' in command.text)):
                            topology_name = command.text.split(' ')[1]
                            self.parent_map[command].remove(command)   
                            
                            topology_commands1 = self.xmlroot.findall("./context0[@name='topology']/context1")
                            for command in topology_commands1:
                                if (command.get('name') == '%s' % topology_name):
            				        self.parent_map[command].remove(command)
                                    
                            roles_commands = self.xmlroot.findall("./context0[name='role']/context1/command")
                            for command in roles_commands:
                                if 'topology-name' in command.text:   
                                    if topology_name in command.text:
                                        self.parent_map[command].remove(command)
                                
                    
    def change_default_cos_value(self):
		default_cos_value_commands = self.xmlroot.findall("./context0[@name='role']/context1/command")
		for command in default_cos_value_commands:
			default_cos = command.text
			if default_cos == 'default-cos "No-CoS"':
				changed_to_command = 'default-cos "No CoS"'
				command.text = changed_to_command
				self.climlogger.info('default-cos: changed from "No-CoS" to "No CoS"\n')
				self.xmltree.write(self.clixml_migrated)
	
    def remove_snmpid(self):
		context0commands = self.xmlroot.findall("./context0/command")
		context1commands = self.xmlroot.findall("./context0/context1/command")
		
		for context0 in context0commands:
			if context0.text.split(' ')[0]=='create':
				if 'snmpid' in context0.text.split(' '):
					changed_to_command = context0.text.split('snmpid')[0]
					context0.text = changed_to_command
					#self.parent_map[context].remove(snmpid_text)
					self.climlogger.info('snmp: snmpid is depreciated %s \n' % changed_to_command)
					self.xmltree.write(self.clixml_migrated)
		
		for context1 in context1commands:
			if context1.text.split(' ')[0]=='create':
				if 'snmpid' in context1.text.split(' '):
					changed_to_command = context1.text.split('snmpid')[0]
					context1.text = changed_to_command
					#self.parent_map[context].remove(snmpid_text)
					self.climlogger.info('snmp: snmpid is depreciated , changed command to: %s \n' % changed_to_command)
					self.xmltree.write(self.clixml_migrated)
					
    def lanset_autofull(self):
        #print self.lanset_autofull.__name__
        '''Non configurables: Always Enabled as Auto full Duplex'''
        rootlevel_commands = self.xmlroot.findall("./rootlevelcommand")        
        
        for rlc in rootlevel_commands:
            if rlc.text.split(' ')[0] == 'lanset' and rlc.text.split(' ')[-1] !='full':
                changed_to_command = rlc.text.split(' ')[0] + ' ' + rlc.text.split(' ')[1] + ' autoneg_on any full'
                rlc.text = changed_to_command
                self.climlogger.info('lanset: always enabled as auto full duplex, changed to "%s"\n' % changed_to_command)
        
        self.xmltree.write(self.clixml_migrated)
    
    
    def fastfailover_enable(self):
        #print self.fastfailover_enable.__name__

        '''Non configurables: fast failover is always enabled'''
        availability_commands= self.xmlroot.findall("./context0[@name='availability']/command") 
        
        for ac in availability_commands:
            if ac.text == 'no fast_failover':
                ac.text = 'fast_failover'
                self.climlogger.info("availability:fast_failover: changed from 'no fast_failover' to 'failover\n")
                self.xmltree.write(self.clixml_migrated)

    def syncmu_enable(self):
        #print self.syncmu_enable.__name__

        '''Non configurables: syncmu is always enabled'''
        availability_commands= self.xmlroot.findall("./context0[@name='availability']/command") 
        
        for ac in availability_commands:
            if ac.text == 'no sync-mu':
                ac.text = 'sync-mu'
                self.climlogger.info("availability:sync-mu: changed from 'no sync-mu' to 'sync-mu\n")
                self.xmltree.write(self.clixml_migrated)
    
    def ap_polltimeout(self, defaultvalue = '80'):
        #print self.ap_polltimeout.__name__

        apcontextcommands = self.xmlroot.findall("./context0[@name='ap']/command") 
        
        for apcc in apcontextcommands:
            if apcc.text.split(' ')[0]=='serial':
                apserial = apcc.text.split(' ')[2]
                findcontext = "./context0[@name='ap']/context1[@name='%s']/command"%apserial
                apserialcontextcommands = self.xmlroot.findall("./context0[@name='ap']/context1[@name='%s']/command"%apserial)
                for apscc in apserialcontextcommands:
                    if apscc.text.split(' ')[0] == 'poll_timeout' and apscc.text.split(' ')[1]!=str(defaultvalue):
                        apscc.text = 'poll_timeout ' + str(defaultvalue)
                        #self.xmltree.write(self.clixml_migrated)
                        self.climlogger.info("ap:%s:poll_timeout: changed to default value %s\n"%(apserial,defaultvalue))
        
        self.xmltree.write(self.clixml_migrated)
                
    def ap_nobcastdisassoc(self):
        #print self.ap_nobcastdisassoc.__name__

        apcontextcommands = self.xmlroot.findall("./context0[@name='ap']/command") 
        
        for apcc in apcontextcommands:
            if apcc.text.split(' ')[0]=='serial':
                apserial = apcc.text.split(' ')[2]
                findcontext = "./context0[@name='ap']/context1[@name='%s']/command"%apserial
                apserialcontextcommands = self.xmlroot.findall("./context0[@name='ap']/context1[@name='%s']/command"%apserial)
                for apscc in apserialcontextcommands:
                    if apscc.text == 'bcast_disassoc':
                        apscc.text = 'no bcast_disassoc'
                        #self.xmltree.write(self.clixml_migrated)
                        self.climlogger.info("ap:%s:bcast_disassoc: AP broadcast disassociation is disabled\n"%apserial)
        
        self.xmltree.write(self.clixml_migrated)
               
    def ap_multicastassembly(self):
        #print self.ap_multicastassembly.__name__

        apcontextcommands = self.xmlroot.findall("./context0[@name='ap']/command") 
        
        for apcc in apcontextcommands:
            if apcc.text.split(' ')[0]=='serial':
                apserial = apcc.text.split(' ')[2]
                findcontext = "./context0[@name='ap']/context1[@name='%s']/command"%apserial
                apserialcontextcommands = self.xmlroot.findall("./context0[@name='ap']/context1[@name='%s']/command"%apserial)
                for apscc in apserialcontextcommands:
                    if apscc.text == 'ipmcast-assembly enable' or apscc.text == 'ipmcast-assembly disable':
                        self.parent_map[apscc].remove(apscc)
                        #self.xmltree.write(self.clixml_migrated)
                        self.climlogger.info("ap:%s:ipmcast-assembly: AP Multicast assembly is depriciated\n"%apserial)
        self.xmltree.write(self.clixml_migrated)

    def ap_lldp(self, default_announceinterval= 30, default_anouncement_delay = 2):
        #print self.ap_lldp.__name__

        
        apcontextcommands = self.xmlroot.findall("./context0[@name='ap']/command") 
        
        for apcc in apcontextcommands:
            if apcc.text.split(' ')[0]=='serial':
                apserial = apcc.text.split(' ')[2]
                findcontext = "./context0[@name='ap']/context1[@name='%s']/command"%apserial
                apserialcontextcommands = self.xmlroot.findall("./context0[@name='ap']/context1[@name='%s']/command"%apserial)
                for apscc in apserialcontextcommands:
                    if apscc.text == 'no lldp':
                        apscc.text = 'lldp %s %s' % (str(default_announceinterval), str(default_anouncement_delay))
                        #self.xmltree.write(self.clixml_migrated)
                        self.climlogger.info("ap:%s:lldp: LLDP is always enabled, %s announce interval, %s announce delay\n"%(apserial,default_announceinterval, default_anouncement_delay))
        
        self.xmltree.write(self.clixml_migrated)

    def ap_maxdistance(self):
        #print self.ap_maxdistance.__name__

        apcontextcommands = self.xmlroot.findall("./context0[@name='ap']/command") 
        
        for apcc in apcontextcommands:
            if apcc.text.split(' ')[0]=='serial':
                apserial = apcc.text.split(' ')[2]
                findcontext_rad1 = "./context0[@name='ap']/context1[@name='%s']/context2[@name='radio1']/command"%apserial
                findcontext_rad2 = "./context0[@name='ap']/context1[@name='%s']/context2[@name='radio2']/command"%apserial

                apserialradio1contextcommands = self.xmlroot.findall(findcontext_rad1)
                apserialradio2contextcommands = self.xmlroot.findall(findcontext_rad2)
                
                for apsr1cc in apserialradio1contextcommands:
                    if apsr1cc.text.split(' ')[0] == 'max-distance':
                        self.parent_map[apsr1cc].remove(apsr1cc)
                        self.climlogger.info("ap:%s:radio1:max-distance: max-distance is depriciated\n"%apserial)
                        
                for apsr2cc in apserialradio2contextcommands:
                    if apsr2cc.text.split(' ')[0] == 'max-distance':
                        self.parent_map[apsr2cc].remove(apsr2cc)
                        self.climlogger.info("ap:%s:radio2:max-distance: max-distance is depriciated\n"%apserial)
                        
        self.xmltree.write(self.clixml_migrated)

    
    def ap_antsel(self):
        #print self.ap_antsel.__name__

        apcontextcommands = self.xmlroot.findall("./context0[@name='ap']/command") 
        
        for apcc in apcontextcommands:
            if apcc.text.split(' ')[0]=='serial':
                apserial = apcc.text.split(' ')[2]
                findcontext_rad1 = "./context0[@name='ap']/context1[@name='%s']/context2[@name='radio1']/command"%apserial
                findcontext_rad2 = "./context0[@name='ap']/context1[@name='%s']/context2[@name='radio2']/command"%apserial

                apserialradio1contextcommands = self.xmlroot.findall(findcontext_rad1)
                apserialradio2contextcommands = self.xmlroot.findall(findcontext_rad2)
                
                for apsr1cc in apserialradio1contextcommands:
                    if apsr1cc.text.split(' ')[0] == 'antsel':
                        self.parent_map[apsr1cc].remove(apsr1cc)
                        self.climlogger.info("ap:%s:radio1:antsel: antsel is depriciated\n"%apserial)
                        
                for apsr2cc in apserialradio2contextcommands:
                    if apsr2cc.text.split(' ')[0] == 'antsel':
                        self.parent_map[apsr2cc].remove(apsr2cc)
                        self.climlogger.info("ap:%s:radio2:antsel: antsel is depriciated\n"%apserial)
                        
        self.xmltree.write(self.clixml_migrated)

    
    def ap_beaconp(self, defaultvalue = 100):
        #print self.ap_beaconp.__name__

        apcontextcommands = self.xmlroot.findall("./context0[@name='ap']/command") 
        
        for apcc in apcontextcommands:
            if apcc.text.split(' ')[0]=='serial':
                apserial = apcc.text.split(' ')[2]
                findcontext_rad1 = "./context0[@name='ap']/context1[@name='%s']/context2[@name='radio1']/command"%apserial
                findcontext_rad2 = "./context0[@name='ap']/context1[@name='%s']/context2[@name='radio2']/command"%apserial

                apserialradio1contextcommands = self.xmlroot.findall(findcontext_rad1)
                apserialradio2contextcommands = self.xmlroot.findall(findcontext_rad2)
                
                for apsr1cc in apserialradio1contextcommands:
                    if apsr1cc.text.split(' ')[0] == 'beaconp' and apsr1cc.text.split(' ')[1] !=str(defaultvalue):                        
                        self.climlogger.info("ap:%s:radio1:beaconp: beaconp is changed to %s from %s\n"%(apserial,str(defaultvalue),apsr1cc.text.split(' ')[1]))
                        apsr1cc.text =  'beaconp %s'%str(defaultvalue)

                for apsr2cc in apserialradio2contextcommands:
                    if apsr2cc.text.split(' ')[0] == 'beaconp' and apsr2cc.text.split(' ')[1] !=str(defaultvalue):                        
                        self.climlogger.info("ap:%s:radio1:beaconp: beaconp is changed to %s from %s\n"%(apserial,str(defaultvalue),apsr2cc.text.split(' ')[1]))
                        apsr2cc.text =  'beaconp %s'%str(defaultvalue)
                
        self.xmltree.write(self.clixml_migrated)  
                
    def ap_n_pmode(self):
        #print self.ap_n_pmode.__name__

        apcontextcommands = self.xmlroot.findall("./context0[@name='ap']/command") 
        
        for apcc in apcontextcommands:
            if apcc.text.split(' ')[0]=='serial':
                apserial = apcc.text.split(' ')[2]
                findcontext_rad1 = "./context0[@name='ap']/context1[@name='%s']/context2[@name='radio1']/command"%apserial
                apserialradio1contextcommands = self.xmlroot.findall(findcontext_rad1)
                
                for apsr1cc in apserialradio1contextcommands:
                    if apsr1cc.text == 'n_pmode none' or apsr1cc.text == 'n_pmode auto':                        
                        self.climlogger.info("ap:%s:radio1:n_pmode: n_pmode is always enabled\n"%apserial)
                        apsr1cc.text =  'n_pmode always'                                        
        self.xmltree.write(self.clixml_migrated)  
                
    def ap_pmode(self):
        #print self.ap_pmode.__name__

        apcontextcommands = self.xmlroot.findall("./context0[@name='ap']/command") 
        
        for apcc in apcontextcommands:
            if apcc.text.split(' ')[0]=='serial':
                apserial = apcc.text.split(' ')[2]
                findcontext_rad2 = "./context0[@name='ap']/context1[@name='%s']/context2[@name='radio2']/command"%apserial
                apserialradio2contextcommands = self.xmlroot.findall(findcontext_rad2)
                
                for apsr2cc in apserialradio2contextcommands:
                    if apsr2cc.text == 'pmode none' or apsr2cc.text == 'pmode auto':                        
                        self.climlogger.info("ap:%s:radio2:pmode: pmode is always enabled\n"%apserial)
                        apsr2cc.text =  'pmode always'                                        
        self.xmltree.write(self.clixml_migrated)      
    
    def ap_n_aggr_msdu(self):
        #print self.ap_n_aggr_msdu.__name__

        apcontextcommands = self.xmlroot.findall("./context0[@name='ap']/command") 
        
        for apcc in apcontextcommands:
            if apcc.text.split(' ')[0]=='serial':
                apserial = apcc.text.split(' ')[2]
                findcontext_rad1 = "./context0[@name='ap']/context1[@name='%s']/context2[@name='radio1']/command"%apserial
                findcontext_rad2 = "./context0[@name='ap']/context1[@name='%s']/context2[@name='radio2']/command"%apserial

                apserialradio1contextcommands = self.xmlroot.findall(findcontext_rad1)
                apserialradio2contextcommands = self.xmlroot.findall(findcontext_rad2)
                
                for apsr1cc in apserialradio1contextcommands:
                    if apsr1cc.text == 'n_aggr_msdu':
                        apsr1cc.text = 'no n_aggr_msdu'
                        self.climlogger.info("ap:%s:radio1:n_aggr_msdu: Always disabled\n"%apserial)
                        
                for apsr2cc in apserialradio2contextcommands:
                    if apsr2cc.text == 'n_aggr_msdu':
                        apsr2cc.text = 'no n_aggr_msdu'
                        self.climlogger.info("ap:%s:radio2:n_aggr_msdu: Always disabled\n"%apserial)
                        
        self.xmltree.write(self.clixml_migrated)
                
    def ap_n_addba_suppodrt(self):
        #print self.ap_n_addba_suppodrt.__name__

        apcontextcommands = self.xmlroot.findall("./context0[@name='ap']/command") 
        
        for apcc in apcontextcommands:
            if apcc.text.split(' ')[0]=='serial':
                apserial = apcc.text.split(' ')[2]
                findcontext_rad1 = "./context0[@name='ap']/context1[@name='%s']/context2[@name='radio1']/command"%apserial
                findcontext_rad2 = "./context0[@name='ap']/context1[@name='%s']/context2[@name='radio2']/command"%apserial

                apserialradio1contextcommands = self.xmlroot.findall(findcontext_rad1)
                apserialradio2contextcommands = self.xmlroot.findall(findcontext_rad2)
                
                for apsr1cc in apserialradio1contextcommands:
                    if apsr1cc.text == 'no n_addba_support':
                        apsr1cc.text = 'n_addba_support'
                        self.climlogger.info("ap:%s:radio1:n_addba_support: Always enabled\n"%apserial)
                        
                for apsr2cc in apserialradio2contextcommands:
                    if apsr2cc.text == 'no n_addba_support':
                        apsr2cc.text = 'n_addba_support'
                        self.climlogger.info("ap:%s:radio2:n_addba_support: Always enabled\n"%apserial)
                        
        self.xmltree.write(self.clixml_migrated)
    
    
    def ap_mode(self):
        #print self.ap_mode.__name__

        apcontextcommands = self.xmlroot.findall("./context0[@name='ap']/command") 
        
        for apcc in apcontextcommands:
            if apcc.text.split(' ')[0]=='serial':
                apserial = apcc.text.split(' ')[2]
                findcontext_rad1 = "./context0[@name='ap']/context1[@name='%s']/context2[@name='radio1']/context3[@name='dcs']/command"%apserial
                findcontext_rad2 = "./context0[@name='ap']/context1[@name='%s']/context2[@name='radio2']/context3[@name='dcs']/command"%apserial

                apserialradio1contextcommands = self.xmlroot.findall(findcontext_rad1)
                apserialradio2contextcommands = self.xmlroot.findall(findcontext_rad2)
                
                for apsr1cc in apserialradio1contextcommands:
                    if apsr1cc.text == 'mode active':
                        apsr1cc.text = 'mode monitor'
                        self.climlogger.info("ap:%s:radio1:dcs:mode: DCS monitor always enabled\n"%apserial)
                        
                for apsr2cc in apserialradio2contextcommands:
                    if apsr2cc.text == 'mode active':
                        apsr2cc.text = 'mode monitor'
                        self.climlogger.info("ap:%s:radio2:dcs:mode: DCS monitor always enabled\n"%apserial)
                        
        self.xmltree.write(self.clixml_migrated)
                
    def ap_eventtype(self):
        #print self.ap_eventtype.__name__

        'only in radio2'
        apcontextcommands = self.xmlroot.findall("./context0[@name='ap']/command") 
        
        for apcc in apcontextcommands:
            if apcc.text.split(' ')[0]=='serial':
                apserial = apcc.text.split(' ')[2]
                findcontext_rad2 = "./context0[@name='ap']/context1[@name='%s']/context2[@name='radio2']/context3[@name='dcs']/command"%apserial

                apserialradio2contextcommands = self.xmlroot.findall(findcontext_rad2)
                        
                for apsr2cc in apserialradio2contextcommands:
                    if apsr2cc.text[0] == 'interference-event-type':
                        if len(apsr2cc.text.split(','))<5: 
                            apsr2cc.text = 'interference-event-type bluetooth, microwave, cordless phone, constant wave, video bridge'
                            self.climlogger.info("ap:%s:radio2:dcs:interference-event-type: Always enabled all type of interference\n"%apserial)      
        self.xmltree.write(self.clixml_migrated)
    
    def ap_loadgroups(self):

        #print self.ap_loadgroups.__name__
    
        loadgroupcontexts = self.xmlroot.findall("./context0[@name='ap']/context1[@name='load-groups']/context2")
        
        for lg in loadgroupcontexts:
            groupname =lg.attrib['name']
            
            lgcontextcommands = self.xmlroot.findall("./context0[@name='ap']/context1[@name='load-groups']/context2[@name='%s']/command"%groupname)
            for lgcc in lgcontextcommands:
                if 'radio-load' in lgcc.text.split(' '):
                    self.parent_map[lgcc].remove(lgcc)
                    self.climlogger.info("ap:load-groups:%s:radio-load: Control of the radio number of clients is depreciated\n"%groupname)
        
        self.xmltree.write(self.clixml_migrated)
       
    
    def wlan_prioritymap(self):
        #print self.wlan_prioritymap.__name__

        wlanscontextcommands = self.xmlroot.findall("./context0[@name='wlans']/command") 
        
        for wcc in wlanscontextcommands:
            
            if wcc.text.split(' ')[0]=='create':
                wlanserv = re.findall(r'"([^"]*)"', wcc.text)[0]
                
                wlanserv='"%s"'%wlanserv
             
                findcontext="./context0[@name='wlans']/context1[@name='%s']/context2[@name='qos-policy']/command"%wlanserv
                qospolicycommands = self.xmlroot.findall(findcontext) 
                for qpc in qospolicycommands:
                    if 'priority-map' in qpc.text.split(' ') and 'dscp' in qpc.text.split(' ') :
                        self.parent_map[qpc].remove(qpc)
                        self.climlogger.info("wlans:%s:qos-policy:priority-map: DSCP to user priority mapping is depreciated\n"%wlanserv)      
        
        self.xmltree.write(self.clixml_migrated)
        
        
    def wlan_priorityoverride(self):
        #print self.wlan_priorityoverride.__name__

        wlanscontextcommands = self.xmlroot.findall("./context0[@name='wlans']/command") 
    
        for wcc in wlanscontextcommands:
            
            if wcc.text.split(' ')[0]=='create':
                wlanserv = re.findall(r'"([^"]*)"', wcc.text)[0]
                
                wlanserv='"%s"'%wlanserv
             
                findcontext="./context0[@name='wlans']/context1[@name='%s']/context2[@name='qos-policy']/command"%wlanserv
                qospolicycommands = self.xmlroot.findall(findcontext) 
                for qpc in qospolicycommands:
                    if qpc.text =='priority-override enable':
                        self.parent_map[qpc].remove(qpc)
                        self.climlogger.info("wlans:%s:qos-policy:priority-override: Priority override is depreciated\n"%wlanserv)      
        self.xmltree.write(self.clixml_migrated)
        
    def wlan_priv(self):
        #print self.wlan_priv.__name__

        wlanscontextcommands = self.xmlroot.findall("./context0[@name='wlans']/command") 
    
        for wcc in wlanscontextcommands:
            
            if wcc.text.split(' ')[0]=='create':
                wlanserv = re.findall(r'"([^"]*)"', wcc.text)[0]                
                wlanserv='"%s"'%wlanserv
                findcontext="./context0[@name='wlans']/context1[@name='%s']/context2[@name='priv']/command"%wlanserv
                privcommands = self.xmlroot.findall(findcontext)
                
                for pc in privcommands:
                    if pc.text =='mode wep' or pc.text=='mode dynwep':
                        pc.text = 'none'
                        self.climlogger.info("wlans:%s:priv:mode: wep and dynwep are depreciated so mode is set to none. Warning: The wlanservice is open.\n"%wlanserv)  
                        
                    if 'wpa-v1' in pc.text.split():
                        pc.text_old= pc.text
                        pc.text = 'wpa-v2 auto'
                        self.climlogger.info("wlans:%s:priv:WPA-v1: WPA-v1 is depreciated. Changed from '%s' to '%s'\n"%(wlanserv, pc.text_old, pc.text)) 
                    
                    if 'wpa-v2-key-mgmt' in pc.text.split():
                        self.climlogger.info("wlans:%s:priv:wpa-v2: WPA-v2-key-mgmt is depreciated\n"%wlanserv) 

                        
        self.xmltree.write(self.clixml_migrated)
        
    def wlan_captiveportal(self):
        #print self.wlan_captiveportal.__name__

        wlanscontextcommands = self.xmlroot.findall("./context0[@name='wlans']/command") 
    
        for wcc in wlanscontextcommands:
            
            if wcc.text.split(' ')[0]=='create':
                wlanserv = re.findall(r'"([^"]*)"', wcc.text)[0]
                
                wlanserv='"%s"'%wlanserv
             
                findcontext="./context0[@name='wlans']/context1[@name='%s']/context2[@name='auth']/context3[@name='captiveportal']"%wlanserv
                captiveportal = self.xmlroot.find(findcontext) 
                
                if captiveportal is not None:
                    self.parent_map[captiveportal].remove(captiveportal)
                    self.climlogger.info("wlans:%s:auth:captiveportal: Captive portal migration is not supported. Professional Service is recommended\n"%wlanserv)      
        
        self.xmltree.write(self.clixml_migrated)
                    
    def wlan_removewlans(self):
        #print self.wlan_removewlans.__name__

        wlans = self.xmlroot.findall("./context0[@name='wlans']") 
        
        for wlan in wlans:                
            wlancommands = self.xmlroot.findall("./context0[@name='wlans']/command")
            for wlc in wlancommands:
                
                if wlc.text.split(' ')[0]=='create' and 'wds' in wlc.text.split(' '):
                    wlanserv = re.findall(r'"([^"]*)"', wlc.text)[0]
                    wlanserv='"%s"'%wlanserv
                    self.parent_map[wlan].remove(wlan)
                    self.climlogger.info("%s WLANservice is removed as 'wds' mode is depreciated. Professional Service is recommended\n"%wlanserv)
                    
                if wlc.text.split(' ')[0]=='create' and '3pap' in wlc.text.split(' '):
                    wlanserv = re.findall(r'"([^"]*)"', wlc.text)[0]
                    wlanserv='"%s"'%wlanserv
                    self.parent_map[wlan].remove(wlan)
                    self.climlogger.info("%s WLANservice is removed as '3pap' mode is depreciated. Professional Service is recommended\n"%wlanserv)
                    
                if wlc.text.split(' ')[0]=='create' and 'remote' in wlc.text.split(' '):
                    wlanserv = re.findall(r'"([^"]*)"', wlc.text)[0]
                    wlanserv='"%s"'%wlanserv
                    self.parent_map[wlan].remove(wlan)
                    self.climlogger.info("%s WLANservice is removed as 'remote' mode is depreciated. Professional Service is recommended\n"%wlanserv)
                    
        self.xmltree.write(self.clixml_migrated)
            
                                                                    
    def role_trafficmirror(self):
        #print self.role_trafficmirror.__name__

        rolecontextcommands = self.xmlroot.findall("./context0[@name='role']/command")    
        for rcc in rolecontextcommands:
            if rcc.text.split(' ')[0]=='create':
                role = re.findall(r'"([^"]*)"', rcc.text)[0]
                
                role='"%s"'%role
             
                findcontext="./context0[@name='role']/context1[@name='%s']/command"%role
                givenrolecommands = self.xmlroot.findall(findcontext) 
                for grc in givenrolecommands:
                    if grc.text == 'traffic-mirror enable':
                        self.parent_map[grc].remove(grc)
                        self.climlogger.info("role:%s:traffic-mirror: Traffic mirroring is depreciated\n"%role)      
        self.xmltree.write(self.clixml_migrated)
        
    def role_egressvlans(self):
        #print self.role_egressvlans.__name__

        rolecontextcommands = self.xmlroot.findall("./context0[@name='role']/command")    
        for rcc in rolecontextcommands:
            if rcc.text.split(' ')[0]=='create':
                role = re.findall(r'"([^"]*)"', rcc.text)[0]
                
                role='"%s"'%role
             
                findcontext="./context0[@name='role']/context1[@name='%s']/command"%role
                givenrolecommands = self.xmlroot.findall(findcontext) 
                for grc in givenrolecommands:
                    if 'egress-vlans' in grc.text.split(' '):
                        self.parent_map[grc].remove(grc)
                        self.climlogger.info("role:%s:egress-vlans: policy egress rule is depreciated\n"%role)      
        self.xmltree.write(self.clixml_migrated)
    
    def role_ulfilterap(self):
        #print self.role_ulfilterap.__name__

        rolecontextcommands = self.xmlroot.findall("./context0[@name='role']/command")    
        for rcc in rolecontextcommands:
            if rcc.text.split(' ')[0]=='create':
                role = re.findall(r'"([^"]*)"', rcc.text)[0]
                
                role='"%s"'%role
             
                findcontext="./context0[@name='role']/context1[@name='%s']/command"%role
                givenrolecommands = self.xmlroot.findall(findcontext) 
                for grc in givenrolecommands:
                    if grc.text == 'ulfilterap enable':
                        self.parent_map[grc].remove(grc)
                        self.climlogger.info("role:%s:ulfilterap: Custom AP filtering is depreciated\n"%role)      
        self.xmltree.write(self.clixml_migrated)
        
    def role_filterstatus(self):
        #print self.role_filterstatus.__name__

        rolecontextcommands = self.xmlroot.findall("./context0[@name='role']/command")    
        for rcc in rolecontextcommands:
            if rcc.text.split(' ')[0]=='create':
                role = re.findall(r'"([^"]*)"', rcc.text)[0]
                
                role='"%s"'%role
             
                findcontext="./context0[@name='role']/context1[@name='%s']/command"%role
                givenrolecommands = self.xmlroot.findall(findcontext) 
                for grc in givenrolecommands:
                    if grc.text == 'filter-status enable':
                        self.parent_map[grc].remove(grc)
                        self.climlogger.info("role:%s:filter-status: inherit filter rules from currently applied role is depreciated\n"%role)      
        self.xmltree.write(self.clixml_migrated)
        
    def role_accesscontrol(self):
        #print self.role_accesscontrol.__name__

        
        rolecontextcommands = self.xmlroot.findall("./context0[@name='role']/command")    
        for rcc in rolecontextcommands:
            if rcc.text.split(' ')[0]=='create':
                role = re.findall(r'"([^"]*)"', rcc.text)[0]
                
                role='"%s"'%role
             
                findcontext="./context0[@name='role']/context1[@name='%s']/command"%role
                givenrolecommands = self.xmlroot.findall(findcontext) 
                for grc in givenrolecommands:
                    if grc.text == 'access-control no-change':
                        grc.text ='access-control deny'
                        self.climlogger.info("role:%s:access-control: 'no change' is depreciated, changed to 'deny'\n"%role)      
        self.xmltree.write(self.clixml_migrated)
    
    def role_accesscontrol_containtovlan(self):
        #print self.role_accesscontrol_containtovlan.__name__

        roles= self.xmlroot.findall("./context0[@name='role']") 
        
        for role in roles:
            change_command_flag = self.check_topology_role(role)
            
            if change_command_flag is True:
                rolecontextcommands = role.findall("command") 
                for rcc in rolecontextcommands:
                    if rcc.text.split(' ')[0]=='create':
                        rolename = re.findall(r'"([^"]*)"', rcc.text)[0]
                        rolename='"%s"'%rolename
                        findcontext="./context0[@name='role']/context1[@name='%s']/command"%rolename
                        givenrolecommands = self.xmlroot.findall(findcontext)
                        for grc in givenrolecommands:
                            if 'contain2vlan' in grc.text.split(' ') and 'access-control' in grc.text.split(' '):
                                self.climlogger.info("role:%s:access-control: '%s' is changed to 'access-control deny' as mixed types of VLAN in a single role is not supported\n"%(rolename, grc.text))      
                                grc.text = 'access-control deny'
        self.xmltree.write(self.clixml_migrated)    
                                                        
    def role_defaultcos(self):
        #print self.role_defaultcos.__name__

        rolecontextcommands = self.xmlroot.findall("./context0[@name='role']/command")    
        for rcc in rolecontextcommands:
            if rcc.text.split(' ')[0]=='create':
                role = re.findall(r'"([^"]*)"', rcc.text)[0]
                
                role='"%s"'%role
             
                findcontext="./context0[@name='role']/context1[@name='%s']/command"%role
                givenrolecommands = self.xmlroot.findall(findcontext) 
                for grc in givenrolecommands:
                    if grc.text == 'default-cos no-change':
                        grc.text ='default-cos "No-CoS"'
                        self.climlogger.info("role:%s:default-cos: 'no change' is depreciated, changed to 'No CoS'\n"%role)      
        self.xmltree.write(self.clixml_migrated)
    
    
    def vnsmode_ruleredirect(self): 
        #print self.vnsmode_ruleredirect.__name__
            
        findcontext="./context0[@name='vnsmode']/context1[@name='adminctr']/command"
        givenvnscommands = self.xmlroot.findall(findcontext) 
        for gvc in givenvnscommands:
            if gvc.text == 'rule-redirect disable':
                gvc.text = 'rule-redirect enable'
                self.climlogger.info("vnsmode:adminctr:rule-redirect: Policy rule redirect is always enabled\n")      
        self.xmltree.write(self.clixml_migrated)
        
    def vnsmode_netflowmirror(self):
        #print self.vnsmode_netflowmirror.__name__

        findcontext="./context0[@name='vnsmode']/context1[@name='netflow-mirror']"
        netflowmirror = self.xmlroot.find(findcontext) 
        self.parent_map[netflowmirror].remove(netflowmirror)
        self.xmltree.write(self.clixml_migrated) 
        self.climlogger.info("vnsmode:netflow-mirror: netflow-mirror is depreciated\n")
    
    def vnsmode_radius(self): 
        #print self.vnsmode_radius.__name__
       
        radiuscontextscommands = self.xmlroot.findall("./context0[@name='vnsmode']/context1[@name='radius']/command") 
        radius_servers=[]
        
        for rcc in  radiuscontextscommands:
            if rcc.text.split( )[0] == 'create': 
                server_name = re.findall(r'"([^"]*)"', rcc.text)[0]
                radius_servers.append(server_name)
                self.climlogger.info("vnsmode:radius: server '%s' is removed from CLI and moved to separete nse configuration file\n"%server_name)
                
        findradiuscontexts="./context0[@name='vnsmode']/context1[@name='radius']"
        radiuscontexts = self.xmlroot.findall(findradiuscontexts) 
        
        for radc in radiuscontexts:            
            self.parent_map[radc].remove(radc)
        
        self.xmltree.write(self.clixml_migrated) 


    def mobility_mrole(self):  
        #print self.mobility_mrole.__name__
                   
        findcontext="./context0[@name='mobility']/command"
        mobilitycommands = self.xmlroot.findall(findcontext)
        
        for mc in mobilitycommands:
            if mc.text == 'mrole manager' or mc.text == 'mrole agent':
                mc.text = 'mrole none'
                #self.xmltree.write(self.clixml_migrated) 
                self.climlogger.info("mobility:mrole: mobility is depreciated\n")     
        self.xmltree.write(self.clixml_migrated) 
       
    def topology_exception(self):
        #print self.topology_exception.__name__

        topologycontextcommands = self.xmlroot.findall("./context0[@name='topology']/command") 
        
        for tcc in topologycontextcommands:
            
            if tcc.text.split(' ')[0]=='create':
                topology = re.findall(r'"([^"]*)"', tcc.text)[0]
                
                topology='"%s"'%topology               
             
                findcontext="./context0[@name='topology']/context1[@name='%s']/context2[@name='l3']/context3[@name='exceptions']"%topology
                exceptioncontexts = self.xmlroot.findall(findcontext)
                
                for excp in exceptioncontexts:
                    self.parent_map[excp].remove(excp)
                    #self.xmltree.write(self.clixml_migrated) 
                    self.climlogger.info("topology:%s:l3:exceptions: Exception filters are depreciated\n"%topology)        
        self.xmltree.write(self.clixml_migrated) 

    def check_wlanmode(self, wlans_element):
       
        
        for command in wlans_element:
            if command.text is not None:
                if 'remote' in command.text.split(' ') or 'wds' in command.text.split(' ') or '3pap' in command.text.split(' '):
                    #print wlans_element.tag, wlans_element.attrib['name'], command.text
                    return True                                    
        return False    
    
    def gettopologies(self):

        
        topologycontext_commands = self.xmlroot.findall("./context0[@name='topology']/command")  
        top_info = []                                              
        
        for command in topologycontext_commands:
            if 'create' in command.text.split(' '):
                top_name = re.findall(r'"([^"]*)"', command.text)
                if 'b@ap' in command.text.split(' '):
                    top_info.append({'name': top_name[0], 'type': 'b@ap'})
                elif 'b@ac' in command.text.split(' '):
                    top_info.append ({'name': top_name[0], 'type': 'b@ac'})
                elif 'routed' in command.text.split(' '): 
                    top_info.append ({'name': top_name[0], 'type': 'routed'})
                elif 'physical' in command.text.split(' '): 
                    top_info.append ({'name': top_name[0], 'type': 'physical'})

        # topology list obtained above is not complete, search for more        
        topologycontext_commands = self.xmlroot.findall("./context0[@name='topology']/context1/command")  
        top_info2 = []                                              
        
        for command in topologycontext_commands:
            if 'name' in command.text.split(' '):
                top_name = re.findall(r'"([^"]*)"', command.text)
                top_info2.append(top_name[0])
        
        for el in top_info2:
            if el not in [x['name'] for x in top_info]:
                top_info.append({'name': el, 'type': 'b@ap'}) # bridge at ap assumed, check it
                
        return top_info
                    
    def check_topology_role(self, role_element):

        '''
        If role and acfilter has same topo type, returns false (condition to change topo type not met) else return true
        '''
        
        topos = self.gettopologies()  
                  
        com1 = role_element.findall("context1/command")# looking for topology-name
        com2 = role_element.findall("context1/context2[@name='acfilters']/command")# looking for set-filter-topology
        
        top_role_type = ' '
        top_filter_type = ' '
        
        for cm1 in com1:
            if cm1.text:
                if 'topology-name' in cm1.text.split(' '):
                    top_name_role = re.findall(r'"([^"]*)"', cm1.text)
                    top_role_type = ' '                    
                    
                    for topo in topos:                        
                        if topo['name']== top_name_role[0]:
                            top_role_type = topo['type']
                            #print 'Topo Info CM1:', top_name_role[0], top_role_type
                  
        for cm2 in com2:
            if cm2.text:
                if 'set-filter-topology' in cm2.text.split(' '): 
                    top_name_filter = re.findall(r'"([^"]*)"', cm2.text)
                    
                    if top_name_filter:
                        top_name_filter = top_name_filter[0]
                    else:
                        top_name_filter = ' '.join(cm2.text.split(' ')[2:])
                    
                    top_filter_type = ' '
                    
                    for topo in topos:
                        if topo['name']== top_name_filter:
                            top_filter_type = topo['type']
                            #print 'Topo Info CM2:', top_name_filter, top_filter_type
        
        if top_role_type != ' ' and top_filter_type != ' ' and top_role_type == top_filter_type:
            return False
        
        return True
           
    def xpathfrom_contex_command(self, context_command):

        
        contexts = context_command['context'].split(':')
                
        context_str = ''
        
        for context in contexts: 
                               
            if context == 'rootlevelcommand':
                context_str = '/rootlevelcommand' 
                                   
            elif context[0] == '<' and context[-1] == '>':
                context_str = context_str+'/context'+ str(contexts.index(context))
                
            else:
                context_str = context_str+'/context'+ str(contexts.index(context))+"[@name='%s']"%context
                                       
        return '.'+ context_str
    
    def skipcommands(self, lod_skipcommands): 
        
        for el in lod_skipcommands:
            #ex_xpath =  self.xmltree.findall("./context0[@name='ap']/context1[@name='12341758905A0000']/context2[@name='radio1']/context3[@name='dcs']/command") 
            skipcommand = el['command']
            
            xpath = self.xpathfrom_contex_command(el)
                        
            if xpath != './rootlevelcommand':
                xpath = xpath+'/command'            
            
            xpathcommands =  self.xmlroot.findall(xpath)
                        
            for xpc in xpathcommands:                
                #print 'Child: ', xpc.text, self.parent_map[xpc].tag, 'Parent: ', self.parent_map[xpc].attrib
                if skipcommand in xpc.text.split(' '):
                    self.parent_map[xpc].remove(xpc)
                    self.climlogger.info('Skipped command, %s Parent context %s Skipped context: %s\n' %(xpc.text, self.parent_map[xpc].attrib, xpath[1:]))
               
        self.xmltree.write(self.clixml_migrated)
                    
    def changecommands(self, lod_changecommands): 
        
        for el in lod_changecommands:
          
            change_context =el['context']
            changecommand = el['command']
            change_fromto = el['fromto']
            from_parm = change_fromto[0]
            to_parm = change_fromto[1]
                        
            change_context0 = "./context0[@name='%s']"%change_context.split(':')[0]
            
            xpath = self.xpathfrom_contex_command(el)
                
            if xpath != './rootlevelcommand':
                xpath = xpath+'/command'            
            
            xpath_ = xpath.replace(change_context0,'')
            
            change_contexts = self.xmlroot.findall(change_context0)
            
            condition_met = True

            for cc in change_contexts:  
                xpathcommands =  cc.findall(xpath_[1:])    
                
                              
                if el['condition'] is not None and 'concheckfxn' in el:                                                           
                    condition_met = self.concheck_dispatcher[el['concheckfxn']](cc)
                    
                    if condition_met:                       
                        #xpathcommands =  cc.findall(xpath_[1:])            
                        for xc in xpathcommands:
                            if changecommand in xc.text.split(' ') and from_parm in xc.text.split(' '):
                                xc.text = xc.text.replace(from_parm,to_parm)
                                self.climlogger.info('Changed command, %s: %s, Prev Val %s'% (change_context, xc.text, from_parm))
                 
                elif el['condition'] is None:
                    for xc in xpathcommands:
                        if changecommand in xc.text.split(' ') and from_parm in xc.text.split(' '):
                            xc.text = xc.text.replace(from_parm,to_parm) 
                            self.climlogger.info('Changed command, %s: %s, Prev Val %s'% (change_context, xc.text, from_parm))
                                                                     
        self.xmltree.write(self.clixml_migrated)
    
    def removecontexts(self, lod_removecontext):        
    
        for el in lod_removecontext:         
            xpath = self.xpathfrom_contex_command(el)            
            xpathcontexts =  self.xmlroot.findall(xpath)
                        
            condition_met = True
                                
            for xpc in xpathcontexts:
                #print xpc.tag, xpc.attrib
                if el['condition'] is not None and 'concheckfxn' in el:
                    condition_met = self.concheck_dispatcher[el['concheckfxn']](xpc)
                    if condition_met: 
                        self.parent_map[xpc].remove(xpc)
                        self.climlogger.info('Removed context, %s'% xpc.attrib)
 
                elif el['condition'] is None:
                    self.parent_map[xpc].remove(xpc)
                    self.climlogger.info('Removed context, %s'% xpc.attrib)
        
        self.xmltree.write(self.clixml_migrated)
                       
    def checkmigratibity(self):
        # If site is already configured, migration can not be done    
        # TODO add any other factors that affect migratibility
        for context in self.xmltree.iter('context0'):        
            if context.attrib['name'] == 'site':
                print 'The provided configuration can not be migrated.'
                return False
            print 'Working on CLI Configuration Migration ...'             
            return True
        
    def confirmgateway(self):
        ipcontextcommands = self.xmlroot.findall("./context0[@name='ip']/command")
        flotornot =''
        for ipcc in ipcontextcommands:
            if ipcc.text.split(' ')[0] == 'route' and ipcc.text.split(' ')[1] =='default':
                
                if len(ipcc.text.split()) == 4:
                    flotornot = ipcc.text.split()[3]
    
                while True:
                    gwchangeprompt = (raw_input('Change static route default gateway %s? [Y/N]:'%ipcc.text.split(' ')[2])).lower()

                    if not gwchangeprompt in ['n', 'y', 'yes', 'no']:
                            print 'Enter Valid Choice'
                            continue
                        
                    else:
                        
                        if gwchangeprompt == 'y' or gwchangeprompt == 'yes':
                                
                                while True:
                                    gwip= raw_input('Enter gateway ip: ')                            
                            
                                    if not self.isvalidip(gwip):
                                        print 'Enter correct ip'
                                        continue
                                    else:
                                        ipcc.text.split()[2] = gwip
                                        ipcc.text = ipcc.text.split()[0]+ ' ' + ipcc.text.split()[1]+ ' '+ gwip+' '+ flotornot
                                        self.xmltree.write(self.clixml_migrated)
                                        break
                        break
                    
    
    def confirmDNS(self):
        dnscontextcommands = self.xmlroot.findall("./context0[@name='host-attributes']/context1[@name='dns']/command")
        
        for dcc in dnscontextcommands:
            if dcc.text.split()[0]=='dns':
                
                while True:
                    dnschangeprompt = (raw_input('Change %s %s ip %s? [Y/N]:'%(dcc.text.split()[0], dcc.text.split()[1], dcc.text.split()[2]))).lower()

                    if not dnschangeprompt in ['n', 'y', 'yes', 'no']:
                            print 'Enter Valid Choice'
                            continue
                        
                    else:
                        
                        if dnschangeprompt == 'y' or dnschangeprompt == 'yes':
                                
                                while True:
                                    dnsip= raw_input('Enter dns ip: ')                            
                            
                                    if not self.isvalidip(dnsip):
                                        print 'Enter correct ip'
                                        continue
                                    else:
                                        dcc.text = 'dns %s %s' % (dcc.text.split()[1], dnsip)
                                        self.xmltree.write(self.clixml_migrated)
                                        break
                        break
                        
        
    
    def confirmIPofalltopologies(self):
                
        topologycontextcommands = self.xmlroot.findall("./context0[@name='topology']/command") 
        
        topologies = ['"Admin"']
        
        for tcc in topologycontextcommands:
            
            if tcc.text.split(' ')[0]=='create':
                topology = re.findall(r'"([^"]*)"', tcc.text)[0]
                
                topology='"%s"'%topology
                
                topologies.append(topology)
        
        for topology in topologies:  
                                
            findcontext="./context0[@name='topology']/context1[@name='%s']/context2[@name='l3']/command"%topology
            lthreecommands = self.xmlroot.findall(findcontext)
            
            for ltc in lthreecommands:
                if ltc.text.split(' ')[0]=='ip' or ltc.text.split(' ')[0]=='foreign-ip':
                    prompt_type = ltc.text.split(' ')[0]
                    prompt_ip = ltc.text.split(' ')[1]
                    
                    while True:
                        
                        ipchangeflag = (raw_input('Change topology:%s:l3: %s %s? [Y/N]:'%(topology, prompt_type, prompt_ip))).lower()
                     
                        if not ipchangeflag in ['n', 'y', 'yes', 'no']:
                            print 'Enter Valid Choice'
                            continue
                                                            
                        else:
                            if ipchangeflag == 'y' or ipchangeflag == 'yes':
                                
                                while True:
                                    mgmtip_usr= raw_input('Enter the IP address (ip/mask): ')                            
                            
                                    if not self.isvalidip(mgmtip_usr):
                                        print 'Enter correct ip address'
                                        continue
                                    else:
                                        ltc.text = 'ip %s' % mgmtip_usr # should also overrite this ip in create command
                                        self.xmltree.write(self.clixml_migrated)
                                        break
                            
                            break
                        
    
    def confirmIPofcontroller(self):
        
     topcontexts = self.xmlroot.findall("./context0[@name='topology']/context1")
     
     for topcontext in topcontexts:
         managmentenable = False

         topname = topcontext.attrib ['name'] 
         topcontextlthreecommands = topcontext.findall("./context2[@name='l3']/command")
         
         for topcontextlthreecommand in topcontextlthreecommands:
             
             if topcontextlthreecommand.text =='mgmt enable':
                managmentenable = True
                
         if managmentenable:
             
             for topcontextlthreecommand in topcontextlthreecommands:
                 
                 if topcontextlthreecommand.text.split(' ')[0] == 'ip':
                     mgmtip = topcontextlthreecommand.text.split(' ')[1]
                     #print 'Management is enable through %s %s'% (topname, topcontextlthreecommand.text.split(' ')[1])
                    
                     while True:
                         ipchangeflag = (raw_input('Change management IP %s? [Y/N]:'%mgmtip)).lower()
                         
                         if not ipchangeflag in ['n', 'y', 'yes', 'no']:
                            print 'Enter Valid Choice'
                            continue
                                                            
                         else:
                            if ipchangeflag == 'y' or ipchangeflag == 'yes':
                                
                                while True:
                                    mgmtip_usr= raw_input('Enter the IP address (ip/mask): ')                            
                            
                                    if not self.isvalidip(mgmtip_usr):
                                        print 'Enter correct ip address'
                                        continue
                                    else:
                                        topcontextlthreecommand.text = 'ip %s' % mgmtip_usr # should also overrite this ip in create command
                                        self.xmltree.write(self.clixml_migrated)
                                        break
                            
                            break
  
    def isvalidip(self, address_with_mask):
                
        import socket 
        
        try:
            socket.inet_aton(address_with_mask.split('/')[0]) # TODO: validate ip mask as well
            return True
                
        except:
            return False
	
	
    def applymigrationlogic(self):
        
        if Climigration.checkmigratibity(self):
            
            Climigration.confirmIPofalltopologies(self) 
            Climigration.confirmDNS(self)  
            Climigration.confirmgateway(self) 
			
            Climigration.healthpoll_enable(self) 
            Climigration.lanset_autofull(self)  
            Climigration.fastfailover_enable(self)
            Climigration.syncmu_enable(self)
			
            Climigration.ap_polltimeout(self)
            Climigration.ap_nobcastdisassoc(self)
            Climigration.ap_multicastassembly(self)
            Climigration.ap_lldp(self)
            Climigration.ap_maxdistance(self)
            Climigration.ap_antsel(self)
            Climigration.ap_beaconp(self)
            Climigration.ap_n_pmode(self)
            Climigration.ap_pmode(self)
            Climigration.ap_n_aggr_msdu(self)
            Climigration.ap_n_addba_suppodrt(self)
            Climigration.ap_mode(self)
            Climigration.ap_loadgroups(self)
            
            Climigration.wlan_prioritymap(self)
            Climigration.wlan_priorityoverride(self)
            Climigration.wlan_priv(self)
            Climigration.wlan_captiveportal(self)
            Climigration.wlan_removewlans(self)
            
            Climigration.role_trafficmirror(self)
            Climigration.role_egressvlans(self)
            Climigration.role_filterstatus(self)
            Climigration.role_ulfilterap(self)
            Climigration.role_accesscontrol(self)
            Climigration.role_accesscontrol_containtovlan(self)
            Climigration.role_defaultcos(self)
            
            Climigration.vnsmode_ruleredirect(self)
            Climigration.vnsmode_netflowmirror(self)
            Climigration.vnsmode_radius(self)
            
            Climigration.mobility_mrole(self)
            Climigration.topology_exception(self) 
	        
            # Newly created functions
            Climigration.remove_snmpid(self)
            Climigration.remove_unsupported_aps(self)
            Climigration.remove_unsupported_ports(self)
            Climigration.change_default_cos_value
            Climigration.change_default_cos_value(self)
		
            #Climigration.confirmIPofcontroller(self)
            
            #Climigration.skipcommands(self, self.rootlevel_skipcommands)
            #Climigration.skipcommands(self, self.apcontext_skipcommands)
            #Climigration.skipcommands(self, self.availabilitycontext_skipcommands)
            #Climigration.skipcommands(self, self.wlancontext_skipcommands)
            #Climigration.skipcommands(self, self.rolecontext_skipcommands)
            #Climigration.skipcommands(self, self.vnsmodecontext_skipcommands)
            #Climigration.skipcommands(self, self.mobilitycontext_skipcommands)
            
            #Climigration.changecommands(self, self.wlancontext_changecommands)
            #Climigration.changecommands(self, self.rolecontext_changecommands)

            #Climigration.removecontexts(self, self.wlancontext_removecontexts)
            #Climigration.removecontexts(self, self.apcontext_removecontexts)
            #Climigration.removecontexts(self, self.vnscontext_removecontexts)
            #Climigration.removecontexts(self, self.topologyecontext_removecontexts)