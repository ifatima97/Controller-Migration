from xml.etree import ElementTree as ET
from climigration.climlogging import get_climlogger
import re
   
class RadiusNacConfig():
    
    def __init__ (self, nac_configxml, wc_configxml):
               
        self.nac_configxml = nac_configxml
        self.wc_configxml = wc_configxml

        self.wc_xmltree = ET.parse(self.wc_configxml)
        self.wc_xmlroot = self.wc_xmltree.getroot()  
        
        self.nac_xmltree = ET.parse(self.nac_configxml)
        self.nac_xmlroot = self.nac_xmltree.getroot() 
              
        self.nac_parent_map = dict((c, p) for p in self.nac_xmltree.getiterator() for c in p)
        
        self.climlogger = get_climlogger()        
           
    def importfromcontroller(self): 
        radiusServer_wc_blank = {'auth-port': '',
                                 'acct-port': '',
                                 'auth-prio': '', 
                                 'acct-prio': '',
                                 'auth-retries': '', 
                                 'acct-retries' : '',
                                 'auth-timeout': '',
                                 'acct-timeout': '',
                                 'interim': '',
                                 'protocol': '',
                                 'shared-secret': '', 
                                 'name': '',
                                 'ip': '',
                                 'fast-failover': '',
                                 'polling-mechanism_user': '',
                                 'poling-mechanism_server':'',
                                 'polling-interval': '' 
                                 }

        radiusServer_nac_blank = {'ipAddress' : '', 
                                  'authPort': '',
                                  'acctPort': '',
                                  'authAccessTypeStr': '',
                                  'timeout': '',
                                  'retries': '',
                                  'radiusAccountingEnabled': 'false', # Does not exit; use Default () true or false
                                  'keepDomainName': 'true', # Does not exit; use Default (true) true or false
                                  'responseWindow': '20', # Does not exit; use Default (20 s)
                                  'disableServerStatus': '',
                                  'disableAccessRequest': '',
                                  'accessRequestUsername': 'fakeUser', # Does not exit; use Default (fakeUser)
                                  'reviveInterval' : '60', # Does not exit; use Default (60 s)
                                  'checkInterval': '',
                                  'numberOfAnswersUntilAlive': '3',# Does not exit; use Default (3);
                                  'requireMessageAuthenticator': 'true', # Does not exit; use Default (checked i.e true); true or false
                                  'dbEncryptedSharedSecret' :'',
                                  'dbEncryptedAccessRequestPassword': ''
                                  }
               
        wc_nac_mapping = {'ipAddress' :'ip', 
                          'authPort': 'auth-port',
                          'acctPort': 'acct-port',
                          'authAccessTypeStr': '', #????????????????? In techtrial it is 'NETWORK_ACCESS'
                          'timeout': 'auth-timeout',
                          'retries': 'auth-retries',
                          'radiusAccountingEnabled': '', 
                          'keepDomainName': '', 
                          'responseWindow': '', 
                          'disableServerStatus': 'poling-mechanism_server', # true or false, true if WLC polling-mechanism status server 
                          'disableAccessRequest': 'polling-mechanism_user', # true or false true if polling-mechanism  actual-user
                          'accessRequestUsername': '', 
                          'reviveInterval' : '', 
                          'checkInterval': 'polling-interval',
                          'numberOfAnswersUntilAlive': '', 
                          'requireMessageAuthenticator': '', 
                          'dbEncryptedSharedSecret' :'shared-secret',
                          'dbEncryptedAccessRequestPassword': ''#?????????????????
                          }
        
        
        xpath_radiuscontext = "./context0[@name='vnsmode']/context1[@name='radius']/context2"
        radiuscontexts = self.wc_xmlroot.findall(xpath_radiuscontext)
        
        radiusServers_wc_lod = []
        radiusServers_nac_lod = []
               
        for rc in radiuscontexts:  
            radiusServer_wc = radiusServer_wc_blank
             
            for rccom in rc.findall('command'):
                
                if rccom.text not in ['exit', 'apply'] and len(rccom.text.split(' '))>1:
                                                            
                    if rccom.text.split(' ')[0]== 'polling-mechanism' and rccom.text.split(' ')[1]=='actual-user': 
                        radiusServer_wc['polling-mechanism_user'] = 'true'
                    
                    elif rccom.text.split(' ')[0]== 'polling-mechanism' and rccom.text.split(' ')[1]=='rfc5997': 
                        radiusServer_wc['polling-mechanism_user'] = 'true'
                    
                    elif rccom.text.split(' ')[0]=='name': 
                        radiusServer_wc[rccom.text.split(' ')[0]] = rccom.text[5:] 
                        
                    elif rccom.text.split(' ')[0]=='ip':
                        ip_noquote = re.findall(r'"([^"]*)"', rccom.text.split(' ')[1])[0] 
                        radiusServer_wc[rccom.text.split(' ')[0]] = ip_noquote
                        
                    else:
                        radiusServer_wc[rccom.text.split(' ')[0]] = rccom.text.split(' ')[1]                     
            
            radiusServers_wc_lod.append(radiusServer_wc.copy())
        radiusServers_elements = self.nac_xmlroot.findall('./radiusServers/RadiusServer')
    
        # Removing existing Radius Servers 
        for rs in radiusServers_elements:
            self.nac_parent_map[rs].remove(rs)
            self.climlogger.debug('Removed Existing RadiusServer in %s\n'%self.nac_configxml)
            self.nac_xmltree.write(self.nac_configxml)
        
        # Add radiusServers from wc to nac config files
        radiusServers_element = self.nac_xmlroot.find('./radiusServers')        

        for aradserv in radiusServers_wc_lod:
            radserv = ET.SubElement(radiusServers_element, 'RadiusServer')
            
            radiusServer_nac = radiusServer_nac_blank
            for nac_key in radiusServer_nac_blank:
                mapped_wc_key = wc_nac_mapping[nac_key]
                if mapped_wc_key != '':
                    mapped_wc_value = aradserv[mapped_wc_key]
                    radiusServer_nac[nac_key] = mapped_wc_value
            
            for key in radiusServer_nac:
                radserv_param = ET.SubElement(radserv, key)
                radserv_param.text = radiusServer_nac[key]
                
        self.nac_xmltree.write(self.nac_configxml)
        self.climlogger.info('Success: Radius Paramaters are Updated in %s from %s\n'% (self.nac_configxml,self.wc_configxml)) 
