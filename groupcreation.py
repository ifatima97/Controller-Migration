from xml.etree import ElementTree as ET
from countrycode import getcountrycode
from climigration.climlogging import get_climlogger
import pandas as pd
import re

class Groupcreation():
    
    def __init__ (self, clixml_migrated, clixml_migration_ip):          
        
        self.clixml   = clixml_migration_ip
        self.xmltree = ET.parse(self.clixml)
        self.xmlroot = self.xmltree.getroot()
        
        self.clixml_migrated = clixml_migrated
        self.xmltree_migrated = ET.parse(self.clixml_migrated)
        self.xmlroot_migrated = self.xmltree_migrated.getroot()
        self.migrated_parent_map = dict((c, p) for p in self.xmltree_migrated.getiterator() for c in p)

        self.climlogger = get_climlogger() 
               
                                   
    def get_apnameserial(self):
        # AP name-serial
        aps_name_serial_lod= []
        anAPdic =[]  
        
        for contextcommand in self.xmlroot.findall("./context0[@name='ap']/command"):            
                temp = contextcommand.text.split(' ') 
                
                if temp[0] == 'serial' and temp[1] == 'import':# and 'FOREIGN' not in temp:
                    
                    apserial = temp[2]
                    #apname = temp[3]
                    
                    apname = re.findall(r'"([^"]*)"', contextcommand.text)[0] 
                                                     
                    anAPdic = {'apserial': apserial, 'apname': apname}
                    ap_name_serial_d = {'apname': apname, 'apserial':apserial}
                    aps_name_serial_lod.append(ap_name_serial_d)
        return aps_name_serial_lod            
    
    def get_apserialstcountry(self):                     
        # AP name-country and sec_tun
        aps_serial_st_country_lod = []
        
        apcontexts = self.xmlroot.findall("./context0[@name='ap']/context1")
        
        for apcontext in apcontexts:
            apserial = apcontext.attrib['name']
            apcontextcommands = apcontext.findall('command')
           
            ap_serial_st_country_d = {'apserial': apserial, 'apcountry': '', 'apsectun': ''}
            
            for apcontextcommand in apcontextcommands:
                
                if 'secure-tunnel' in apcontextcommand.text.split(' '):
                   apsectun =  apcontextcommand.text.split(' ')[1]
                   ap_serial_st_country_d['apsectun'] = apsectun                                             
                   
                if 'country' in apcontextcommand.text.split(' '):
                    #apcountry = apcontextcommand.text.split(' ')[1]
                    apcountry = apcontextcommand.text[8:] # leave 'country ' from the start of the string # Commit 1
                    
                    ap_serial_st_country_d['apcountry'] = apcountry
                    aps_serial_st_country_lod.append(ap_serial_st_country_d)  
        return aps_serial_st_country_lod

    def get_allapspecific_dgroupingparams(self):
        aps_name_serial_lod = Groupcreation.get_apnameserial(self)
        aps_serial_st_country_lod = Groupcreation.get_apserialstcountry(self)
        
        aps_name_serial_d = {}
        
        for el in  aps_name_serial_lod:
            aps_name_serial_d[el['apserial']] = el['apname']
                       
        for el in aps_serial_st_country_lod: 
            serial = el['apserial'] 
            name = aps_name_serial_d[serial]
            el['apname'] = name          

        return aps_serial_st_country_lod
    
    def get_loadgroups(self):
        
        ''' list of {'loadgroup': name, 'wlanservices': [], 'aps': [], bpflag': 'enable/disable'}'''
                
        bp_flag = 'disable'

        load_groups = self.xmlroot.findall("./context0[@name='ap']/context1[@name='load-groups']/context2") 
        group_wlanserv_lod = []
               
        for load_group in load_groups:
            load_group_name = load_group.attrib['name']
            
            load_group_commands = load_group.findall('command') 
            wlanservs=[]
            aps = []
            
            for load_group_command in load_group_commands:
                if load_group_command.text.split(' ')[0]=='assign-wlan':
                    wlanservs.append(''.join(load_group_command.text.split(' ')[2:]))
                
                if load_group_command.text.split(' ')[0]=='assign-ap':
                    aps.append(''.join(load_group_command.text.split(' ')[2:]))
                   
                if load_group_command.text.split == 'bandpreference enable':
                    bp_flag = 'enable'
            
            group_wlanserv_entry = {'loadgroup':load_group_name, 'wlanservices': wlanservs, 'aps': aps, 'bpflag': bp_flag} 
            group_wlanserv_lod.append(group_wlanserv_entry)
        
        return group_wlanserv_lod
    
    def get_roles(self):
                
        roles = []
        rolecontexts = self.xmlroot.findall("./context0[@name='role']")
        
        for rolecontext in rolecontexts:
            rolecontextcommands = rolecontext.findall('command')
            for rcc in rolecontextcommands:
                temp = rcc.text.split(' ')
                if temp[0] == 'create':
                    #role = temp[1] 
                    role = re.findall(r'"([^"]*)"', rcc.text)[0]
                    if role:
                        roles.append(role)                        

        return roles
    
    def get_wlanservices(self):
        
        wlanservices = []        
        wlans = self.xmlroot.findall("./context0[@name='wlans']")

        for wlan in wlans:
            wlancommands = wlan.findall('command')
            
            for wlancommand in wlancommands:
                temp = wlancommand.text.split(' ')

                if temp[0] == 'create':
                    wlanserv = re.findall(r'"([^"]*)"', wlancommand.text)[0]
                    #wlanserv = temp[1]
                    apsinwlanserv = []  
                    
                    wlancontext1commands = wlan.findall("./context1/command")
                    
                    for wlancontext1command in wlancontext1commands:

                        temp1 = wlancontext1command.text.split(' ')
                        temp = [x for x in temp1 if x] # filtering empty strings
                        
                        if temp[0] == 'aplist':                                                        
                            apname_tt_l= re.findall(r'"([^"]*)"', wlancontext1command.text) 
                            apname_tt = apname_tt_l[0]
                            apname_ttt = '"%s"'%apname_tt
                            wlancontext1command_minusapname = wlancontext1command.text.replace('"%s"'%apname_tt,'')
                            
                            rorp_tt = wlancontext1command_minusapname.split(' ')[2:]                               
                            apentry = {'apname': apname_tt, 'rorp': rorp_tt}
                            #apentry = {'apname': temp[1], 'rorp': temp[2:]} 

                            apsinwlanserv.append(apentry) 
                                 
                        elif temp[0] == 'aplist-wds':    
                            apentry = {'apname': temp[1], 'rorp': ['none']}
                            #apentry = {'apname': temp[1], 'rorp': ['rorp NA']}
                            apsinwlanserv.append(apentry)
                        
                    wlanservice = {'wlanserv': wlanserv, 'apsinwlanserv': apsinwlanserv}
                    wlanservices.append(wlanservice)  
                    
        return  wlanservices   
    
    def get_defaultpolicy(self, wlanserv):  
        for vnscontext in self.xmlroot.findall("./context0[@name='vnsmode']"):
            vnscontextcommands = vnscontext.findall("command")
            
            for vnscc in vnscontextcommands:
                if vnscc.text.split(' ')[0]=='create':                    
                    vns_wns_pol_names = re.findall(r'"([^"]*)"', vnscc.text)
                    #wlanserv_from_cliline = '"%s"'%vns_wns_pol_names[1]
                    wlanserv_from_cliline = vns_wns_pol_names[1]                      
                    if  wlanserv_from_cliline  == wlanserv:
                        defaultpolicy = vns_wns_pol_names[2]  
                        return defaultpolicy 
                    
    def check_bandpref(self, ap, wlanserv):

        bp_flag = 'disable'
        loadgroups_lod = self.get_loadgroups()
        
        for el in loadgroups_lod:
            wlanservs = el['wlanservices']
            bp_flag = el['bpflag']
            aps = el['aps']
            
            if bp_flag == 'enable':
                if ap in aps and wlanserv in wlanservs:
                    return bp_flag
        
        return bp_flag
    
    def check_port_rad(self, wlanserv, ap):
        
        wlanservs = self.get_wlanservices()
        aps_name_rorp_d = {}
        
        portorrad = 'APnotinWLAN'
                
        for el in wlanservs:
            if el['wlanserv'] == wlanserv:               
                aps_name_rorp_lod = el['apsinwlanserv']  
                
                if  aps_name_rorp_lod:
                    for ell in aps_name_rorp_lod:               
                        dic_entry = {ell['apname']: [x for x in ell['rorp'] if x]}
                        #dic_entry = {ell['apname']: ell['rorp']}
                        aps_name_rorp_d.update(dic_entry)
                        
                    try:
                        portorrad = aps_name_rorp_d[ap]
        
                    except:
                        portorrad = 'APnotinWLAN'                    
                    
        return portorrad
    
    def prompt_country(self, apcountries, apnames):
        
        apcountries_type = list(set(apcountries))
        
        if len(apcountries_type)>1:
            print 'APs are found to have %s different countries'%len(apcountries_type)
            for i, j in zip(apnames, apcountries):
                print i, j
            
            while True:                
                ui_country_qa = raw_input('Do you want to set a same country across all APs?[Y/N]') 
                
                if ui_country_qa.lower()=='y' or ui_country_qa.lower()=='yes':
                    
                    while True:
                        for el in apcountries_type:
                            print el
                            
                        ui_country_val = raw_input("Select one country from above")

                        if ui_country_val in apcountries_type:                            
                            apcountries = [ui_country_val for el in apcountries]   
                            self.change_configxml_country(ui_country_val)                 
                            return apcountries
                        
                        else:
                            print "Enter valid choice"
                            continue
                        
                elif ui_country_qa.lower()=='n' or ui_country_qa.lower()=='no':
                    return apcountries
                 
                else:
                    print 'Enter valid choice'
                    continue
                
        elif len(apcountries_type)== 1:
            return apcountries
            
    
    def change_configxml_securetunnel(self, securetunnel_val):
        
        apcontext1commands = self.xmlroot_migrated.findall("./context0[@name='ap']/context1/command")
        
        for apconetxt1command in apcontext1commands:
            if apconetxt1command.text.split (' ')[0] == 'secure-tunnel':
                apconetxt1command.text = 'secure-tunnel %s'% securetunnel_val   
                
        self.xmltree_migrated.write(self.clixml_migrated)
    
    def change_configxml_country(self, country_val):
        apcontext1commands = self.xmlroot_migrated.findall("./context0[@name='ap']/context1/command")
        
        for apconetxt1command in apcontext1commands:
            if apconetxt1command.text.split (' ')[0] == 'country':
                apconetxt1command.text = 'country %s'% country_val   
                
        self.xmltree_migrated.write(self.clixml_migrated)
        
        
    def prompt_securetunnel(self, apsectunnels, apnames):    
        apsectunnels_type = list(set(apsectunnels))
        
        if len(apsectunnels_type)>1:
            print 'APs are found to have %s different secure-tunnel settings'%len(apsectunnels_type)
            for i, j in zip(apnames, apsectunnels):
                print i, j
            
            while True:                
                ui_sec_tunnel_qa = raw_input('Do you want to make secure-tunnel parameter uniform across all APs?[Y/N]') 
                
                if ui_sec_tunnel_qa.lower()=='y' or ui_sec_tunnel_qa.lower()=='yes':
                    
                    
                    while True:
                        ui_sec_tunnel_val = raw_input("Select one among 'disable', 'control', 'debug' and 'data' ")
                        prob_sec_tun_param = ['disable', 'control', 'debug', 'data']

                        if ui_sec_tunnel_val.lower() in prob_sec_tun_param:                            
                            apsectunnels = [ui_sec_tunnel_val for el in apsectunnels]  
                            self.change_configxml_securetunnel(ui_sec_tunnel_val)                   
                            return apsectunnels
                        
                        else:
                            print "Enter valid choice"
                            continue
                        
                elif ui_sec_tunnel_qa.lower()=='n' or ui_sec_tunnel_qa.lower()=='no':
                    return apsectunnels
                 
                else:
                    print 'Enter valid choice'
                    continue
        elif len(apsectunnels_type) == 1:
            return apsectunnels
                    
    def createdevgroups(self):
        print 'Creating Device Groups....'
        
        devgroups_lod = []

        aps_serial_name_st_country = self.get_allapspecific_dgroupingparams()
        index_apnames = [el['apname'] for el in aps_serial_name_st_country]
        apserials = [el['apserial'] for el in aps_serial_name_st_country]
        apsectunnels = [el['apsectun'] for el in aps_serial_name_st_country]
        apcountries = [el['apcountry'] for el in aps_serial_name_st_country]
            
        apsectunnels = self.prompt_securetunnel(apsectunnels, index_apnames)
        apcountries = self.prompt_country(apcountries, index_apnames)  
                        
        wlanservices = self.get_wlanservices()
        roles = self.get_roles()
        ws_grpcnd = {} # grouping conditions for given wlanservs and aps
        
        #for elwlanserv in wlanservices:
        #    print elwlanserv['wlanserv']
        #    for apel in elwlanserv['apsinwlanserv']:
        #        print apel
        
        for ws in wlanservices:
            rorp_apsinwlanserv = [0] * len(index_apnames)
            grpcnd_apsinwlanserv = [0] * len(index_apnames)                 

            aps = ws['apsinwlanserv']            
            apsinwlanserv  = [el['apname'] for el in aps]
            rorpinwlanserv = [el['rorp'] for el in aps] 
        
            #print  ws['wlanserv'], apsinwlanserv, rorpinwlanserv
        
            for idx, el in enumerate(index_apnames): 
                bp_flag = self.check_bandpref(ws['wlanserv'], el)                    
                radorport = self.check_port_rad(ws['wlanserv'], el) 
                cntry = apcountries[index_apnames.index(el)]
                sectun = apsectunnels[index_apnames.index(el)] 
                cntry = cntry.replace(' ','') 
                
                if el in apsinwlanserv:                                    
                    #print ws['wlanserv'], el, bp_flag,sectun,cntry, radorport                    
                    grpcnd = [radorport, bp_flag, sectun, cntry]
                    grpcnd_ =  " ".join(str(x) for x in grpcnd)                       
                    grpcnd_apsinwlanserv[idx] = grpcnd_   
                else:
                    #print ws['wlanserv'], el, radorport
                    grpcnd_apsinwlanserv[idx] = radorport
                    
            ws_grpcnd.update({ws['wlanserv']:grpcnd_apsinwlanserv})                      
        ws_grpcnd_df = pd.DataFrame(ws_grpcnd, index =  index_apnames)
        devicegroups = ws_grpcnd_df.groupby(ws_grpcnd_df.columns.values.tolist())
        #print ws_grpcnd_df
        #print ws_grpcnd_df.columns.values.tolist()     
        #print len(devicegroups),'\n\n', devicegroups.groups,'\n\n', type(devicegroups.groups)
        
        # If there are aps which are assigned to none of the wlans as noticed in  206365_techsupport              
        for grpcnd, aplist in devicegroups.groups.items():
            if len(set(grpcnd)) == 1 and grpcnd[0]=='APnotinWLAN':
                del devicegroups.groups[grpcnd]
                         
        groupcount = 0 
        for grpcnd, aplist in devicegroups.groups.iteritems():
            # this typecheck is added for the case when there is only one grpcndn. in this case grpcnd is str other wise it is tuple, # noticed while testing with 205138_C25_tech_support file
			if type(grpcnd) == str:
				grpcnd = (grpcnd,)
			groupcount = groupcount + 1
			groupName = 'DeviceGroup_%s' % groupcount         
			wlansingroup = []
			wlansingroup_rorp = []
                        
            #wlans in a group
			for i, j in enumerate(grpcnd):   
				print 'HELLO 2: %s %s' % (i,j)
				if j != 'APnotinWLAN': 
					#print groupName, i, j, ws_grpcnd_df.columns.values.tolist()[i]
					wlansingroup.append(ws_grpcnd_df.columns.values.tolist()[i])
					rorp_l = j.split(' ')[:-3]  # 3rd from las bp, 2nd from last sec tun, last country, rest: rorp
					rorp = "".join(str(x) for x in rorp_l)
					rorp = rorp.replace('[','') 
					rorp = rorp.replace(']','') 
					rorp = rorp.replace("'",'')  
					rorp = rorp.replace(",",' ')  
					wlansingroup_rorp.append(rorp) 
					# country and sec tunnel val will be same for all apps in a group; can be obtained from an element of grpcnd
					country_forthegroup = j.split(' ')[-1]
					countrycode_forthegroup =  getcountrycode(country_forthegroup)
					sectun_forthegroup = j.split(' ')[-2]
					bandpref_forthegroup = j.split(' ')[-3]
				else:
					countrycode_forthegroup = ' '
					bandpref_forthegroup = ' ' 
					sectun_forthegroup = ' '
                                        
            #Default policies in a group           
			policy_group = []                        
			for el in wlansingroup:
				policy = self.get_defaultpolicy(el) 
				policy_group.append(policy) 
			policy_group_duprem = list(set(policy_group))
            
            # aplist name to serial conversion    
            
            #print apserials
            #for el in aplist:
            #    print 'groupcount: %s, %s %s'%( groupcount, el, index_apnames.index(el) )

			aplist_serial = [apserials[index_apnames.index(el)] for el in aplist]

			devgroup =  {
                         'groupname': groupName,
                         'wlansingroup': wlansingroup,
                         'wlansrorpingroup': wlansingroup_rorp,
                         'apsingroup_name': aplist,
                         'apsingroup': aplist_serial,
                         'defaultpolicy': policy_group_duprem,
                         'countrycode': countrycode_forthegroup,
                         'bandpref': bandpref_forthegroup,
                         'sectunnel': sectun_forthegroup
                         }

			devgroups_lod.append(devgroup) 
            
        #print 'Based on the config files provided %s device groups are created'% (len(devgroups_lod))
        
        #log device group information
        self.climlogger.info('\nBased on the provided cli files %s device groups are created:\n'% (len(devgroups_lod)))
        for el in devgroups_lod:
            self.climlogger.info('Groupname: %s' % el['groupname'])
            self.climlogger.info('WLANS in group: %s' % el['wlansingroup'])
            self.climlogger.info('Radio/port of WLANS in group: %s' % el['wlansrorpingroup'])                        
            self.climlogger.info('APs in group: %s' % el['apsingroup_name'])
            self.climlogger.info('Band preference: %s' % el['bandpref'])
            self.climlogger.info('Secure tunnel: %s' % el['sectunnel'])
            self.climlogger.info('Country Code: %s\n' % el['countrycode'])
     
        #for el in devgroups_lod:
        #    self.climlogger.info(el)
        
        return devgroups_lod
    
    
    def writedevgroups(self, devgroups_lod):
        
              
        for devgroup in devgroups_lod:
            
            sitecontext0 = ET.Element('context0')
            sitecontext0.set('name', 'site')
            self.xmlroot.append(sitecontext0) 
            self.xmlroot_migrated.append(sitecontext0)
            
            self.appendcommand(sitecontext0, 'create "%s"' % devgroup['groupname'])
            sitecontext1 = self.appendcontext(sitecontext0, 'context1', "%s" % devgroup['groupname']) 
                          
            self.appendcommand(sitecontext1, 'band-preference %s' % devgroup['bandpref'] )
            
            for ap in devgroup['apsingroup']:
                self.appendcommand(sitecontext1, 'assign-ap add "%s"' % ap)
                
            for policy in devgroup['defaultpolicy']:
                self.appendcommand(sitecontext1, 'assign-policy add "%s"' % policy)
    
            for ws, wsr in zip(devgroup['wlansingroup'], devgroup['wlansrorpingroup']):           
                self.appendcommand(sitecontext1, 'assign-wlan %s %s' % (ws, wsr))
                
            self.appendcommand(sitecontext1, 'secure-tunnel %s' % devgroup['sectunnel'])
            self.appendcommand(sitecontext1, 'country %s'% devgroup['countrycode'])
            self.appendcommand(sitecontext1, 'apply')
            self.appendcommand(sitecontext1, 'end')   
        
        self.xmltree_migrated.write(self.clixml_migrated)
            
    def appendcommand(self, context, commandtext):  
        command = ET.SubElement(context, 'command')
        command.text = commandtext
        
    def appendcontext(self, parentcontext, contextlevel, contexttext):
        context = ET.SubElement(parentcontext, contextlevel)
        context.set('name', contexttext)
        return context          