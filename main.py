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
from nssrc.com.citrix.netscaler.nitro.resource.config.reputation import reputationsettings
from nssrc.com.citrix.netscaler.nitro.resource.config.ns.nsmode import nsmode
from nssrc.com.citrix.netscaler.nitro.resource.config.ns.nsfeature import nsfeature

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
            print(protocol)
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
            responderpolicy1.rule = "HTTP.REQ.FULL_HEADER.DECODE_USING_TEXT_MODE.REGEX_MATCH(re#((\\${)((\\${)\?((upper|lower|(env)\?:.*:.*})\?[jJlLnNdDiIaApPsSmMrRoOhH}:]*))+)//#)"
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
            responderpolicy2.rule = "HTTP.REQ.URL.PATH_AND_QUERY.DECODE_USING_TEXT_MODE.REGEX_MATCH(re#((\\${)((\\${)\?((upper|lower|(env)\?:.*:.*})\?[jJlLnNdDiIaApPsSmMrRoOhH}:]*))+)//#)"
            responderpolicy2.logaction = "Log4Shell_URL_log"
            responderpolicy2.add(ns_session, responderpolicy2)

        except Exception as error:
            errormessage = ("Error: " + str(error.args))
            print(errormessage)

        try:
            bind_responderpolicy1_global = responderglobal_responderpolicy_binding.responderglobal_responderpolicy_binding()
            bind_responderpolicy1_global.policyname = "GLOVR_RSP_POL_Log4Shell_Headers"
            bind_responderpolicy1_global.priority = "100"
            bind_responderpolicy1_global.type = "REQ_OVERRIDE"
            bind_responderpolicy1_global.add(ns_session, bind_responderpolicy1_global)
        except Exception as error:
            errormessage = ("Error: " + str(error.args))
            print(errormessage)

        try:
            bind_responderpolicy2_global = responderglobal_responderpolicy_binding.responderglobal_responderpolicy_binding()
            bind_responderpolicy2_global.policyname = "GLOVR_RSP_POL_Log4Shell_URL"
            bind_responderpolicy2_global.priority = "110"
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
                print("4")
                bind_responderpolicy2_global.policyname = "GLOVR_RSP_POL_Log4Shell_URL"
                if bind_responderpolicy2_global.globalbindtype != '':
                    print(bind_responderpolicy2_global.globalbindtype)
                    print("4-1")
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
        nsfeature_enable = nsfeature()
        nsfeature_enable.enable(nsfeature_enable.feature('rep'))
        nsfeature.update_resource(ns_session, nsfeature_enable)

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
        self.title = "Turbo_Log4j_ADC 0.1.0"
        self.icon = "Images/Logo.png"
        Builder.load_file('Log4j_ADC.kv')

    def change_screen(self, screen: str):
        self.root.current = screen


Log4j_ADC().run()