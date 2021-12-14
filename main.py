#Screen functionality gets sent to different files e.g. ADCTK_ReportFunctionality or ADCTK_SecurityScan
#When functionality is done, data gets fed back to the screen and shown to user

#Please mind that the draw time of the screen impacts what is shown, as it does not update dynamically

###############
####Imports####
###############

#Import Kivy libraries
from kivymd.app import MDApp
from kivy.lang import Builder

from kivy.uix.screenmanager import ScreenManager,Screen
from kivy.core.window import Window

#Import List Libaries
from kivymd.uix.list import IRightBodyTouch, OneLineAvatarIconListItem
from kivymd.uix.selectioncontrol import MDCheckbox
from kivy.properties import StringProperty

#Libraries from Netscaler Nitro API
from nssrc.com.citrix.netscaler.nitro.service.nitro_service import nitro_service
from nssrc.com.citrix.netscaler.nitro.resource.config.audit import auditsyslogparams
from nssrc.com.citrix.netscaler.nitro.resource.config.audit import auditnslogparams
from nssrc.com.citrix.netscaler.nitro.resource.config.audit import auditmessageaction
from nssrc.com.citrix.netscaler.nitro.resource.config.responder import responderpolicy
from nssrc.com.citrix.netscaler.nitro.resource.config.responder import responderglobal_responderpolicy_binding
from nssrc.com.citrix.netscaler.nitro.resource.config.appfw import appfwpolicy
from nssrc.com.citrix.netscaler.nitro.resource.config.appfw import appfwglobal_appfwpolicy_binding
from nssrc.com.citrix.netscaler.nitro.resource.config.policy import  policypatset
from nssrc.com.citrix.netscaler.nitro.resource.config.policy import policypatset_pattern_binding
#Window Manager, managed and creates windows via KV file
class WindowManager(ScreenManager):
    pass

#Define CustomListItem for SSL login option
class ListItemWithCheckbox(OneLineAvatarIconListItem):
    '''Custom list item.'''
    icon = StringProperty("security-network")

class RightCheckbox(IRightBodyTouch, MDCheckbox):
    '''Custom right container.'''


class LoginScreen(Screen):

    def submitinfo(self):

        global nsip
        global nsusername

        nsip = self.ids.ns_ip.text
        nsusername = self.ids.ns_username.text
        nspassword = self.ids.ns_password.text


        try:
            global ns_session

            if self.ids.https_box.ids.cb.active == True:
                protocol = "https"
            else:
                protocol = "http"

            ns_session = nitro_service(f"{nsip}", f"{protocol}")
            ns_session.login(f"{nsusername}", f"{nspassword}", 3600)
            return (ns_session.isLogin())

        except Exception as error:

            errormessage = ("Error: " + str(error.args))
            self.ids.error_label_login.text = errormessage

    def cleardata(self):
        self.ids.ns_ip.text = ("")
        self.ids.ns_username.text = ("")
        self.ids.ns_password.text = ("")

class MainMenu(Screen):

    def MadsRegex(self):
        try:
            #Set audit syslogparams to YES
            syslog_params = auditsyslogparams.auditsyslogparams()
            syslog_params.userdefinedauditlog = "YES"
            syslog_params.update(ns_session, syslog_params)
        except Exception as error:
            errormessage = ("Error: " + str(error.args))
            print(errormessage)
        try:
            #Set audit nslogparams to YES
            nslog_params = auditnslogparams.auditnslogparams()
            nslog_params.userdefinedauditlog = "YES"
            nslog_params.update(ns_session, nslog_params)
        except Exception as error:
            errormessage = ("Error: " + str(error.args))
            print(errormessage)

        try:
            #Create Audit Message action #1
            audit_message_action1 = auditmessageaction.auditmessageaction()
            audit_message_action1.name = "Log4Shell_URL_log"
            audit_message_action1.loglevel = "ALERT"
            audit_message_action1.logtonewnslog = "YES"
            audit_message_action1.stringbuilderexpr = "\"Log4Shell  cve-2021-44228 URL match - Client IP=\"+ CLIENT.IP.SRC + \"; REQ Host=\"+ HTTP.REQ.HOSTNAME+ \"; REQ URL=\"+ HTTP.REQ.URL.DECODE_USING_TEXT_MODE + \" ; REQ HEADERS=\"+ HTTP.REQ.FULL_HEADER.DECODE_USING_TEXT_MODE"
            audit_message_action1.add(ns_session, audit_message_action1)
        except Exception as error:
            errormessage = ("Error: " + str(error.args))
            print(errormessage)
        try:
            audit_message_action2 = auditmessageaction.auditmessageaction()
            audit_message_action2.name = "Log4Shell_Headers_log"
            audit_message_action2.loglevel = "ALERT"
            audit_message_action2.logtonewnslog = "YES"
            audit_message_action2.stringbuilderexpr = "\"Log4Shell  cve-2021-44228 HEADER  match - Client IP=\"+ CLIENT.IP.SRC + \"; REQ Host=\"+ HTTP.REQ.HOSTNAME+ \"; REQ URL=\"+ HTTP.REQ.URL.DECODE_USING_TEXT_MODE + \" ; REQ HEADERS=\"+ HTTP.REQ.FULL_HEADER.DECODE_USING_TEXT_MODE"
            audit_message_action2.add(ns_session, audit_message_action2)

        except Exception as error:
            errormessage = ("Error: " + str(error.args))
            print(errormessage)


        try:
            #Create Responder policy GLOVR_RSP_POL_Log4Shell_Headers
            responderpolicy1 = responderpolicy.responderpolicy()
            responderpolicy1.name = "GLOVR_RSP_POL_Log4Shell_Headers"
            responderpolicy1.action = "DROP"
            responderpolicy1.rule = "HTTP.REQ.FULL_HEADER.DECODE_USING_TEXT_MODE.REGEX_MATCH(re#\\$\\{+\?(.*\?:|.*\?:.*-)\?[jJlLnNdDiIaApPsSmMrRoOhH}:]*//#)"
            responderpolicy1.logaction = "Log4Shell_Headers_log"
            responderpolicy1.add(ns_session, responderpolicy1)

        except Exception as error:
            errormessage = ("Error: " + str(error.args))
            print(errormessage)

        try:
            # Create Responder policy GLOVR_RSP_POL_Log4Shell_Headers
            responderpolicy2 = responderpolicy.responderpolicy()
            responderpolicy2.name = "GLOVR_RSP_POL_Log4Shell_URL"
            responderpolicy2.action = "DROP"
            responderpolicy2.rule = "HTTP.REQ.URL.PATH_AND_QUERY.DECODE_USING_TEXT_MODE.REGEX_MATCH(re#\\$\\{+\?(.*\?:|.*\?:.*-)\?[jJlLnNdDiIaApPsSmMrRoOhH}:]*//#)"
            responderpolicy2.logaction = "Log4Shell_URL_log"
            responderpolicy2.add(ns_session, responderpolicy2)

        except Exception as error:
            errormessage = ("Error: " + str(error.args))
            print(errormessage)

        try:
            bind_responderpolicy1_global = responderglobal_responderpolicy_binding.responderglobal_responderpolicy_binding()
            bind_responderpolicy1_global.policyname = "GLOVR_RSP_POL_Log4Shell_Headers"
            bind_responderpolicy1_global.priority = "90"
            bind_responderpolicy1_global.type = "REQ_OVERRIDE"
            bind_responderpolicy1_global.add(ns_session, bind_responderpolicy1_global)
        except Exception as error:
            errormessage = ("Error: " + str(error.args))
            print(errormessage)

        try:
            bind_responderpolicy2_global = responderglobal_responderpolicy_binding.responderglobal_responderpolicy_binding()
            bind_responderpolicy2_global.policyname = "GLOVR_RSP_POL_Log4Shell_URL"
            bind_responderpolicy2_global.priority = "100"
            bind_responderpolicy2_global.type = "REQ_OVERRIDE"
            bind_responderpolicy2_global.add(ns_session, bind_responderpolicy2_global)
        except Exception as error:
            errormessage = ("Error: " + str(error.args))
            print(errormessage)


    def MadsRegexPurge(self):
        i = 0
        while i < 6:
            i+= 1
            try:
                # Set audit syslogparams to No
                syslog_params = auditsyslogparams.auditsyslogparams()
                syslog_params.userdefinedauditlog = "NO"
                syslog_params.update(ns_session, syslog_params)
            except Exception as error:
                errormessage = ("Error1: " + str(error.args))
                print(errormessage)

            try:
                # Set audit nslogparams to No
                nslog_params = auditnslogparams.auditnslogparams()
                nslog_params.userdefinedauditlog = "NO"
                nslog_params.update(ns_session, nslog_params)
            except Exception as error:
                errormessage = ("Error2: " + str(error.args))
                print(errormessage)

            #Remove Global Bindings
            try:
                bind_responderpolicy1_global = responderglobal_responderpolicy_binding.responderglobal_responderpolicy_binding()
                bind_responderpolicy1_global.policyname = "GLOVR_RSP_POL_Log4Shell_Headers"
                if bind_responderpolicy1_global.globalbindtype != "":
                    bind_responderpolicy1_global.globalbindtype = ""
                bind_responderpolicy1_global.delete(ns_session, bind_responderpolicy1_global)

            except Exception as error:
                errormessage = ("Error3: global policies1 " + str(error.args))
                print(errormessage)

            try:
                bind_responderpolicy2_global = responderglobal_responderpolicy_binding.responderglobal_responderpolicy_binding()
                bind_responderpolicy2_global.policyname = "GLOVR_RSP_POL_Log4Shell_URL"
                if bind_responderpolicy2_global.globalbindtype != '':
                    print(bind_responderpolicy2_global.globalbindtype)
                    bind_responderpolicy2_global.globalbindtype = ''
                    bind_responderpolicy2_global.delete(ns_session, bind_responderpolicy2_global)

            except Exception as error:
                errormessage = ("Error4: global policies2 " + str(error.args))
                print(errormessage)

            try:

                audit_message_action1 = auditmessageaction.auditmessageaction()
                audit_message_action1.name = "Log4Shell_URL_log"
                audit_message_action1.unset = "Log4Shell_URL_log"
                audit_message_action1.delete(ns_session, audit_message_action1)

            except Exception as error:
                errormessage = ("Error5: " + str(error.args))
                print(errormessage)

            try:
                audit_message_action2 = auditmessageaction.auditmessageaction()
                audit_message_action2.name = "Log4Shell_Headers_log"
                audit_message_action2.unset = "Log4Shell_Headers_log"
                audit_message_action2.delete(ns_session, audit_message_action2)

            except Exception as error:
                errormessage = ("Error6: " + str(error.args))
                print(errormessage)

            #Remove Responder polcies but remove logaction first
            try:
                responderpolicy1 = responderpolicy.responderpolicy()
                responderpolicy1.name = "GLOVR_RSP_POL_Log4Shell_Headers"
                responderpolicy1.logaction = "None"
                responderpolicy1.unset = "GLOVR_RSP_POL_Log4Shell_Headers"
                responderpolicy1.delete(ns_session, responderpolicy1)

            except Exception as error:
                errormessage = ("Error7: " + str(error.args))
                print(errormessage)

            try:
                responderpolicy2 = responderpolicy.responderpolicy()
                responderpolicy2.name = "GLOVR_RSP_POL_Log4Shell_URL"
                responderpolicy2.logaction = "None"
                responderpolicy2.unset = "GLOVR_RSP_POL_Log4Shell_URL"
                responderpolicy2.delete(ns_session, responderpolicy2)

            except Exception as error:
                errormessage = ("Error8: " + str(error.args))
                print(errormessage)



    def Enable_IP_Reputation(self):

        features_to_be_enabled = ['Rep', 'appfw']
        ns_session.enable_features(features_to_be_enabled)


        try:
            custom_appfw_pol = appfwpolicy.appfwpolicy()
            custom_appfw_pol.name = "Turbo_ADC_Custom_APPFW"
            custom_appfw_pol.profilename = "APPFW_BLOCK"
            custom_appfw_pol.rule = "CLIENT.IP.SRC.IPREP_IS_MALICIOUS"
            custom_appfw_pol.add(ns_session, custom_appfw_pol)
        except Exception as error:
            errormessage = ("Error appfw1: " + str(error.args))

        try:
            bind_appfw_global = appfwglobal_appfwpolicy_binding.appfwglobal_appfwpolicy_binding()
            bind_appfw_global.policyname = "Turbo_ADC_Custom_APPFW"
            bind_appfw_global.state = "ENABLED"
            bind_appfw_global.type = "REQ_OVERRIDE"
            bind_appfw_global.priority = "110"
            bind_appfw_global.add(ns_session, bind_appfw_global)

        except Exception as error:
            errormessage = ("Error appfw2: " + str(error.args))
            print(errormessage)



    def Disable_IP_Reputation(self):

        #features_to_be_disabled = ['Rep']
        #ns_session.disable_features(features_to_be_disabled)

        try:
            bind_appfw_global = appfwglobal_appfwpolicy_binding.appfwglobal_appfwpolicy_binding()
            bind_appfw_global.policyname = "Turbo_ADC_Custom_APPFW"
            bind_appfw_global.state = "DISABLED"
            bind_appfw_global.delete(ns_session, bind_appfw_global)
        except Exception as error:
            errormessage = ("Error appfw2: " + str(error.args))
            print(errormessage)

        try:
            custom_appfw_pol = appfwpolicy.appfwpolicy()
            custom_appfw_pol.name = "Turbo_ADC_Custom_APPFW"
            custom_appfw_pol.delete(ns_session, custom_appfw_pol)
        except Exception as error:
            errormessage = ("Error appfw1: " + str(error.args))


    def Citrix_Responder_Enable(self):

        try:
            #Creates Policy for Patset per https://www.citrix.com/blogs/2021/12/13/guidance-for-reducing-apache-log4j-security-vulnerability-risk-with-citrix-waf/
            policy = policypatset.policypatset()
            policy.name = "patset_cve_2021_44228"
            policy.add(ns_session, policy)
            print("done1")
        except Exception as error:
            errormessage = ("Error citrix1: " + str(error.args))
            print(errormessage)

        try:
            patternset_protocol = policypatset_pattern_binding.policypatset_pattern_binding()
            patternset_protocol.name = "patset_cve_2021_44228"
            patternset_protocol.String = "ldap"
            patternset_protocol.add(ns_session, patternset_protocol)
            patternset_protocol.String = 'http'
            patternset_protocol.add(ns_session, patternset_protocol)
            patternset_protocol.String = 'https'
            patternset_protocol.add(ns_session, patternset_protocol)
            patternset_protocol.String = 'ldaps'
            patternset_protocol.add(ns_session, patternset_protocol)
            patternset_protocol.String = 'rmi'
            patternset_protocol.add(ns_session, patternset_protocol)
            patternset_protocol.String = 'dns'
            patternset_protocol.add(ns_session, patternset_protocol)

        except Exception as error:
            errormessage = ("Error citrix2: " + str(error.args))
            print(errormessage)

        try:
            #Create Responder policy based on patsets
            responder = responderpolicy.responderpolicy()
            responder.name = 'mitigate_cve_2021_44228'
            responder.rule = "HTTP.REQ.FULL_HEADER.SET_TEXT_MODE(URLENCODED).DECODE_USING_TEXT_MODE.AFTER_STR(\"${\").BEFORE_STR(\"}\").CONTAINS(\"${\") || HTTP.REQ.FULL_HEADER.SET_TEXT_MODE(URLENCODED).DECODE_USING_TEXT_MODE.SET_TEXT_MODE(IGNORECASE).STRIP_CHARS(\"${: }/+\").AFTER_STR(\"jndi\").CONTAINS_ANY(\"patset_cve_2021_44228\") || HTTP.REQ.BODY(8192).SET_TEXT_MODE(URLENCODED).DECODE_USING_TEXT_MODE.AFTER_STR(\"${\").BEFORE_STR(\"}\").CONTAINS(\"${\") || HTTP.REQ.BODY(8192).SET_TEXT_MODE(URLENCODED).DECODE_USING_TEXT_MODE. SET_TEXT_MODE(IGNORECASE).STRIP_CHARS(\"${: }/+\").AFTER_STR(\"jndi\").CONTAINS_ANY(\"patset_cve_2021_44228\")"
            responder.action = "DROP"
            responder.add(ns_session, responder)

        except Exception as error:
            errormessage = ("Error citrix3: " + str(error.args))
            print(errormessage)

        try:
            #Bind Responder policy globally
            bind_responderpolicy_global = responderglobal_responderpolicy_binding.responderglobal_responderpolicy_binding()
            bind_responderpolicy_global.policyname = "mitigate_cve_2021_44228"
            bind_responderpolicy_global.priority = "120"
            bind_responderpolicy_global.type = "REQ_OVERRIDE"
            bind_responderpolicy_global.add(ns_session, bind_responderpolicy_global)
        except Exception as error:
            errormessage = ("Error citrix4: " + str(error.args))
            print(errormessage)

    def Citrix_Responder_Purge(self):

        try:
            #Bind Responder policy globally
            bind_responderpolicy_global = responderglobal_responderpolicy_binding.responderglobal_responderpolicy_binding()
            bind_responderpolicy_global.policyname = "mitigate_cve_2021_44228"
            if  bind_responderpolicy_global.globalbindtype != '':
                print(bind_responderpolicy_global.globalbindtype)
                bind_responderpolicy_global.globalbindtype = ''
                bind_responderpolicy_global.delete(ns_session, bind_responderpolicy_global)

        except Exception as error:
            errormessage = ("Error citrix4: " + str(error.args))
            print(errormessage)

        try:
            #Create Responder policy based on patsets
            responder = responderpolicy.responderpolicy()
            responder.name = 'mitigate_cve_2021_44228'
            responder.delete(ns_session, responder)

        except Exception as error:
            errormessage = ("Error citrix4: " + str(error.args))
            print(errormessage)


        try:
            patternset_protocol = policypatset_pattern_binding.policypatset_pattern_binding()
            patternset_protocol.name = "patset_cve_2021_44228"
            patternset_protocol.String = "ldap"
            patternset_protocol.delete(ns_session, patternset_protocol)
            patternset_protocol.String = 'http'
            patternset_protocol.delete(ns_session, patternset_protocol)
            patternset_protocol.String = 'https'
            patternset_protocol.delete(ns_session, patternset_protocol)
            patternset_protocol.String = 'ldaps'
            patternset_protocol.delete(ns_session, patternset_protocol)
            patternset_protocol.String = 'rmi'
            patternset_protocol.delete(ns_session, patternset_protocol)
            patternset_protocol.String = 'dns'
            patternset_protocol.delete(ns_session, patternset_protocol)

        except Exception as error:
            errormessage = ("Error citrix2: " + str(error.args))
            print(errormessage)

        try:
            #Creates Policy for Patset per https://www.citrix.com/blogs/2021/12/13/guidance-for-reducing-apache-log4j-security-vulnerability-risk-with-citrix-waf/
            policy = policypatset.policypatset()
            policy.name = "patset_cve_2021_44228"
            policy.delete(ns_session, policy)

        except Exception as error:
            errormessage = ("Error citrix1: " + str(error.args))
            print(errormessage)

    def Save_NS_Config(self):
        ns_session.save_config()

    def Logout_NS_Session(self):
        ns_session.logout()

#Build Class for Login Screen inc. Theme data
class Log4j_ADC(MDApp):

    def build(self):
        #Window.size = (1200, 800)
        self.theme_cls.theme_style = "Dark"
        self.theme_cls.primary_palette = "Blue"
        self.theme_cls.hue = 700
        self.title = "Turbo_Log4j_ADC 1.1"
        self.icon = "Images/Logo.png"
        Builder.load_file('Log4j_ADC.kv')

    def change_screen(self, screen: str):
        self.root.current = screen


Log4j_ADC().run()
