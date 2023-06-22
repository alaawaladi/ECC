
import os, sys, django,optparse,logging,time,traceback
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "email_recovery.settings")
django.setup()


from django.conf import settings
from urllib import response
from MySQLdb import Date
import requests,re
import logging
import socket
import warnings
import datetime,time
from bs4  import BeautifulSoup
import time
import os, random, json
import pickle, string
from recovery.models import DatasetSession

warnings.filterwarnings("ignore")

logging.basicConfig(level=logging.INFO)
logging = logging.getLogger("yahoo")


class Yahoo:
    
    codes_response = {
        200 : 'OK',201: 'Created',202: 'Accepted',203: 'Non-Authoritative Information',204: 'No Content',
        205: 'Reset Content',206: 'Partial Content',300: 'Multiple Choices',301: 'Moved Permanently',302: 'Moved Temporarily',
        303: 'See Other',304: 'Not Modified',305: 'Use Proxy',400: 'Bad Request',401: 'Unauthorized',402: 'Payment Required',
        403: 'Access Forbidden',404: 'Not Found',405: 'Method Not Allowed',406: 'Not Acceptable',407: 'Proxy Authentication Required',
        408: 'Request Time-out',409: 'Conflict',410: 'Gone',411: 'Length Required',412: 'Precondition Failed',
        413: 'Request Entity Too Large',414: 'Request-URI Too Large',415: 'Unsupported Media Type',500: 'Internal Server Error',
        501: 'Not Implemented',502: 'Bad Gateway',503: 'Service Unavailable',504: 'Gateway Time-out',505: 'HTTP Version not supported'
    }

    def __init__(self, email, pwd, proxy, port,UserAgent,email_reco, owner_id=0):
        self.email = email
        self.pwd = pwd
        self.proxy = proxy
        self.port = port
        self.url = "https://mail.yahoo.com/"
        self.UserAgent = UserAgent
        self.email_reco = email_reco
        self.owner_id = owner_id

        #...SET time GMT
        os.environ['TZ'] = 'Greenwich Standard Time'
        time.tzset()
        
        self.headers = {
            "User-Agent":self.UserAgent,
            "Accept":"*/*",
            "Accept-Encoding"  :  "gzip, deflate, br",
            "Accept-Language"   : "fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3",
            "Connection":"keep-alive",
        }

        # GLOBAL DATA POST
        self.messages = []
        self.existsContacts = []
        self._YUI_BOXES = {'Inbox':{}, 'Bulk':{}}
        self.toHex = 1

        #...Test proxy conenction
        self.test_proxy()

        #...Global session
        self.session = requests.Session()

    def test_proxy(self):
        # ...Proxy Connection
        self.status_proxy = True
        self.proxies = {
            "http": f"http://{str(self.proxy)}:{str(self.port)}/",
            "https": f"http://{str(self.proxy)}:{str(self.port)}/",
        }
        self.s = socket.socket()
        try:
            logging.info(f"[{self.email}] Trying {self.proxy}")
            self.s.settimeout(10)
            self.s.connect((self.proxy, self.port))
            logging.info(f"[{self.email}] [{self.proxy}] Proxy is OK")
        except:
            logging.warning(f"[{self.email}] [{self.proxy}] proxy is Not OK")
            self.status_proxy = False

    def run_requests(self, url, action='GET', **kwargs):

        try:
            if action=='GET': 
                response = self.session.get(url, **kwargs)
            else: 
                response = self.session.post(url, **kwargs)

            return True, response

        except requests.exceptions.SSLError as e:
            return False, f"SslError ({str(e)})!"
        except requests.exceptions.ProxyError as e:
            return False, f"ProxyError [{self.proxy}] ({str(e)})!"
        except requests.exceptions.Timeout:
            return False, "Service Timeout If the problem persists, contact support"        
        except Exception as e:
            return False, f"Exception running request ({str(e)})"

    def session_validation(self):
        connected = False
        if(os.path.isfile(settings.SESSION_PATH+self.email)):
            try:
                with open(os.path.join(settings.SESSION_PATH+self.email), 'rb') as f:
                    self.session = pickle.load(f)
                    if self.isConnected():
                        connected = True
                        logging.info(f"[{self.email}] Success connected from session . . .")
                        self.store_session()
            except EOFError as eof:
                logging.error(f"[{self.email}] EOFError ({str(eof)})")
            except Exception as e:
                logging.error(f"[{self.email}] Exception [session_validation] ({str(e)})")
        else:
            logging.info(f"[{self.email}] Session not found start Login process . . .")
            obj = DatasetSession.objects.filter(email=self.email)
            if obj:
                is_expired = obj.values('expired')[0]
                if is_expired:
                    is_expired = is_expired['expired']
                    if not is_expired:
                        DatasetSession.objects.filter(email=self.email).update(expired=datetime.datetime.now())
        return connected

    def remove_session(self):
        try:
            os.remove(os.path.join(settings.SESSION_PATH+self.email))
            DatasetSession.objects.filter(email=self.email).update(expired=datetime.datetime.now())
        except:
            pass

    def store_session(self):

        if not os.path.isdir(settings.SESSION_PATH) :
            try:
                os.makedirs(settings.SESSION_PATH,0o775)
            except Exception as e :
                logging.warning(f"[{self.email}] Create session folder failed! ({str(e)})") 

        try:
            with open(os.path.join(settings.SESSION_PATH+self.email), 'wb') as f:
                pickle.dump(self.session, f)
                logging.info(f"[{self.email}] Session success saved")  
                _, created = DatasetSession.objects.get_or_create(email=self.email, defaults={'add_by':self.owner_id})
                if not created:
                    is_expired = DatasetSession.objects.filter(email=self.email).values('expired')[0]
                    is_expired = is_expired['expired']
                    if is_expired:
                        DatasetSession.objects.filter(email=self.email).update(created=datetime.datetime.now(), modified=datetime.datetime.now(), expired=None)
                    else:
                        DatasetSession.objects.filter(email=self.email).update(modified=datetime.datetime.now(), expired=None)
                return True
        except Exception as e:
            logging.error(f"[{self.email}] Exception [store_session] {str(e)}")
        return False

    def status_msg(self,code):
        if code in self.codes_response:
            return self.codes_response[code]
        return f"Unknown error , code #{code}"
    
    def checkStatusResponse(self, response, msglog):
        if response == "" or response.status_code != 200:
            logging.warning(f"[{self.email}] [{self.proxy}] {msglog} (Server response : {self.status_msg(response.status_code)})")
            return False
        return True

    def Get_PayLoad(self,rq_Content):
        posted_data = {}
        html = BeautifulSoup(rq_Content)
        inputs =  html.find_all("input", attrs={'type':'hidden'})
        for input in inputs:
            try:
                posted_data[input.attrs['name']]=input.attrs['value']
            except:
                posted_data[input.attrs['name']]=""
        return posted_data 
         
    def login(self):  

        if not self.status_proxy: return False
        
        logging.info(f"[{self.email}] Start login session . . .")
        connected = self.session_validation()
        
        if not connected :
            self.session.headers.update({
                "User-Agent":self.UserAgent,
                "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language":"en-US,en;q=0.5",
                "Accept-Encoding":"gzip, deflate",
                "Content-Type":"application/x-www-form-urlencoded",
                "Upgrade-Insecure-Requests": '1'
            })
            url_login = "https://login.yahoo.com"
            status, rsp = self.run_requests(url_login , allow_redirects=True,proxies=self.proxies,verify=False)
            if not status:
                logging.warning(f"[{self.email}] login requests failed! ({rsp})")
                return False 

            if not self.checkStatusResponse(rsp, "Start new session"):
                return False

            # check if there is second signin url
            _reg_signin_URL = re.compile("<a href=\"(https:\//login.yahoo.com\?\.src=ym&amp;pspid=([0-9]+)&amp;activity=header-signin&[^\"]+)\"")
            resfetch = re.search(_reg_signin_URL, rsp.text)
            if resfetch:
                url_login = resfetch.group(1)
                logging.info(f"[{self.email}] login with this url: {url_login}")
                status, rsp = self.run_requests(url_login , allow_redirects=True,proxies=self.proxies,verify=False)
                if not status:
                    logging.warning(f"[{self.email}] second signin url requests failed! ({rsp})")
                    return False 
                
                if not self.checkStatusResponse(rsp, "Start session with other login url"):
                    return False
            
            # check if login form exit
            _reg_login_form = re.compile('<form id="login-username-form"' )  
            if not re.search(_reg_login_form, rsp.text):
                logging.warning(f"[{self.email}] Yahoo Start Session Failed!.") 
                return False
            
            logging.info(f"[{self.email}] Yahoo Session started.") 

            # step 1
            #... Get Posted parameter from HTML
            posted_data = self.Get_PayLoad(rsp.text)
            if posted_data and 'crumb' in posted_data:
                self.crumb = posted_data['crumb']
                step_username_url = rsp.url
                posted_data.update({"username":self.email})
                browser_ft_data = {"language":"en-US","colorDepth":24,"deviceMemory":"unknown","pixelRatio":1,"hardwareConcurrency":8,"timezoneOffset":0,"timezone":"UTC","sessionStorage":1,"localStorage":1,"indexedDb":1,"cpuClass":"unknown","platform":"Win32","doNotTrack":"unspecified","plugins":{"count":5,"hash":"2c14024bf8584c3f7f63f24ea490e812"},"canvas":"canvas winding:yes~canvas","webgl":1,"webglVendorAndRenderer":"Google Inc. (Intel)~ANGLE (Intel, Intel(R) HD Graphics Direct3D11 vs_4_1 ps_4_1)","hasLiedLanguages":0,"hasLiedResolution":0,"hasLiedOs":0,"hasLiedBrowser":0,"touchSupport":{"points":0,"event":0,"start":0},"fonts":{"count":51,"hash":"83a367664df09821b3cf93ad809eda4c"},"audio":"35.7383295930922","resolution":{"w":"1920","h":"1080"},"availableResolution":{"w":"1040","h":"1920"},"ts":{"serve":1670334193102,"render":1670334193373}}
                posted_data.update({"browser-fp-data": browser_ft_data})
                posted_data["passwd"] = ""
                posted_data["signin"] = "Next"
                # remove keep signed in
                if "persistent" in posted_data: del posted_data["persistent"]

                #posted_data["persistent"] = "y"

                logging.info(f"[{self.email}] Start step1 username url ({step_username_url})")
                status, rsp_1 = self.run_requests(step_username_url, action='POST', data=posted_data, proxies=self.proxies, allow_redirects=True, verify=False)
                if not status:
                    logging.warning(f"[{self.email}] signin post requests failed! ({rsp_1})")
                    return False 

                if not self.checkStatusResponse(rsp_1, "Step username status..."):
                    return False

                html = BeautifulSoup(rsp_1.text, "html.parser")
                text_message = html.find("iframe",attrs={'id':'recaptcha-iframe'})
                if text_message:
                    logging.warning(f"[{self.email}] Submit username Failed! recaptcha validation needed")
                    return False

                if "account/challenge/arkose" in rsp_1.text:
                    logging.warning(f"[{self.email}] Security check to complete validation needed")
                    return False

                if self.email.lower() not in rsp_1.text:
                    logging.warning(f"[{self.email}] Submit Username Failed!")
                    return False

                logging.info(f"[{self.email}] success step1 username")
                # step 2
                #... Get Posted parameter from HTML
                step_password_url = rsp_1.url
                logging.info(f"[{self.email}] Start step2 password url ({step_password_url})")

                posted_data = self.Get_PayLoad(rsp_1.text)
                posted_data.update({"username":self.email , "password":self.pwd, "verifyPassword" : "Next"})
                posted_data.update({"browser-fp-data": browser_ft_data})

                status, resp_2 = self.run_requests(step_password_url, action='POST', data=posted_data, proxies=self.proxies, allow_redirects=True, verify=False)
                if not status:
                    logging.warning(f"[{self.email}] signin post requests failed! ({resp_2})")
                    return False 

                if not self.checkStatusResponse(resp_2, "Step password status..."):
                    return False

                if "challenge-selector-challenge" in resp_2.text:
                    logging.warning(f"[{self.email}] challenge to complete validation needed")
                    return False

                html = BeautifulSoup(resp_2.text, "html.parser")
                text_message = html.find("p",attrs={'data-error':'messages.ERROR_NOTFOUND'})
                if "account-health-check" not in resp_2.url and (text_message or "Yahoo | Mail" not in resp_2.text):
                    error_message = text_message.getText().strip() if text_message else resp_2.url
                    logging.warning(f"[{self.email}] Submit password Failed! verification needed! {error_message}")
                    return False

                logging.info(f"[{self.email}] success step2 password")
                
                if self.isConnected():
                    # --> store the session
                    status = self.store_session()
                    return True
            else:
                logging.warning(f"[{self.email}] Logged Failure with posted data: {posted_data}")
                return False
        else:
            return True
        return False
                        
    def isConnected(self,attemps = 0):
        try:
            status, resp_2 = self.run_requests(self.url,allow_redirects=True,proxies=self.proxies, verify=False)
            if not status:
                logging.warning(f"[{self.email}] isConnected requests failed! ({resp_2})")
                return False 
            
            if  resp_2.status_code == 200:
                if not re.search(r'^(https)|(http)\:\/\/mail\.yahoo\.com\/d',resp_2.url):
                    logging.warning(f"[{self.email}] Logged Failure-10 : login url not found")
                    #self.remove_session()
                    return False
                
            res_wssid = re.search(re.compile(r'"mailWssid"\:\"([^\"]+)') , resp_2.text)
            res_uuid = re.search(re.compile(r'"(?:loginHash|guidHash)"\:\"([^\"]+)'), resp_2.text)

            if res_wssid:
                self.wssid =  res_wssid.group(1)
            else:
                logging.warning(f"[{self.email}] Logged Failure to get wssid!")
                #self.remove_session()
                return False

            if res_uuid:
                yq = res_uuid.group(1)
                self.yquid_1 = f"{yq[0:8]}-{yq[8:12]}-{yq[12:16]}-{yq[16:20]}"
                self.yquid = f"{self.yquid_1}-{yq[20:]}"
            else:
                logging.warning(f"[{self.email}] Logged Failure to get yquid!")
                #self.remove_session()
                return False

            regex_crumb = re.search(re.compile(r'<input type="hidden" name="crumb" value="([^\"]+)">'), resp_2.text)
            if regex_crumb:
                self.crumb = regex_crumb.group(1)
            else:
                logging.warning(f"[{self.email}] Logged Failure to get crumb!")
                #self.remove_session()
                return False

            res_V3Mailbox = re.search(re.compile(r'"selectedMailbox":{"id":\"(.+?)\"'  ), resp_2.text)
            if res_V3Mailbox:
                self.V3MailboxId = res_V3Mailbox.group(1)
            else:
                logging.warning(f"[{self.email}] Logged to get V3MailboxId!")
                #self.remove_session()
                return False
            
            if self.crumb and self.V3MailboxId:
                logging.info(f"[{self.email}] Logged in.")
                return True

        except Exception as e:
            logging.warning(f"[{self.email}] Logged Failed with exception! {e}")

        return False
    
    def logout(self):
        logging.info(f"[{self.email}] Start Logout process . . .")   
        url = f'https://login.yahoo.com/account/logout?logout_all=1&src=ym&crumb={self.crumb}&.done=https://www.yahoo.com/' 

        status, resp = self.run_requests(url,allow_redirects=True,verify=False,proxies=self.proxies)
        if not status:
            logging.warning(f"[{self.email}] logout requests failed! ({resp})")
            return 0,1 

        if resp.status_code == 200:
            logging.info(f"[{self.email}] Logout Success.")
        else:
            logging.warning(f"[{self.email}] Logout failed {resp.status_code}")
        
        self.session.close()
        DatasetSession.objects.filter(email=self.email).update(expired=datetime.datetime.now())
        if os.path.exists(settings.SESSION_PATH + self.email):
            try:
                os.remove(settings.SESSION_PATH + self.email)
            except:
                pass
        
        return 1,1

    def hexAlgo(self):
        self.toHex += 1
        x = hex(self.toHex).lstrip("0x").rstrip("L")
        diff = 4 - len(str(x))
        hex4 = "0"*diff + str(x)
        return hex4

    def hash_generator(self, size=8, chars=string.ascii_lowercase + string.digits):
        return ''.join(random.choice(chars) for _ in range(size))
    
    def fresh_yquid(self):
        return f"{self.yquid_1}-{self.hexAlgo()}"

    def get_folders(self):
        """ Get existing folders """   

        _linkApi = f"https://mail.yahoo.com/ws/v3/batch?name=mailbox.sync&hash={self.hash_generator()}&appId=YMailNorrin&ymreqid={self.fresh_yquid()}&wssid={self.wssid}"
        logging.info(f"[{self.email}] GetFolders with url ({_linkApi})")
        
        headers_up = self.session.headers
        headers_up['Content-Type']="application/json"
        _payload='{"requests":[{"id":"GetFolders","uri":"/ws/v3/mailboxes/@.id=='+self.V3MailboxId+'/folders","method":"GET","payloadType":"embedded"}],"responseType":"json"}'
        status, _responseFolders = self.run_requests(_linkApi,action='POST', data=_payload,proxies=self.proxies,allow_redirects=True,verify=False,headers=headers_up)
        if not status:
            logging.warning(f"[{self.email}] get_folders requests failed! ({_responseFolders})")
            return False

        if not self.checkStatusResponse(_responseFolders, "Step Mailbox GetFolders..."):
            return False

        try:
            myResult = _responseFolders.json()
            _res = myResult['result']['responses'][0]['response']['result']
            for fld in _res['folders']:
                if "name" in fld:
                    self._YUI_BOXES[fld['name']] =fld
                else:
                    logging.warning(f"[{self.email}] GetFolders Failed to parsz json content!")
                    return False 
            return True
        except Exception as e:
            logging.warning(f"[{self.email}] GetFolders Exception ({str(e)})")
            return False  

    def get_messages(self, fld, dateParam, subjectParam):
        """ get message list by folder """

        logging.info(f"[{self.email}] Start getting {fld} messages...")

        _linkApi = f"https://mail.yahoo.com/ws/v3/batch?name=folderChange.getList&hash={self.hash_generator()}&appId=YMailNorrin&ymreqid={self.fresh_yquid()}&wssid={self.wssid}"
        exitWhile = False 
        _start = 0
        _perPage = 25
        self.messages = []
        self.session.headers.update({
                        "Accept":"application/json",
                        "Content-Type" : "application/json"
                        })

        if self.get_folders():
            try:
                _total = self._YUI_BOXES[fld]['total']
                folderId = self._YUI_BOXES[fld]['id']
                
                while not exitWhile:
                    _payload = {"requests":[{"id":"GetMessageGroupList","uri":"/ws/v3/mailboxes/@.id=="+self.V3MailboxId+"/messages/@.select==q?q=folderId%3A"+str(folderId)+"%20acctId%3A1%20groupBy%3AconversationId%20count%3A"+str(_perPage)+"%20offset%3A"+str(_start)+"%20-folderType%3A(SYNC)-folderType%3A(INVISIBLE)%20-sort%3Adate","method":"GET","payloadType":"embedded"},{"id":"UnseenCountReset","uri":"/ws/v3/mailboxes/@.id=="+self.V3MailboxId+"/decos/@.id==FTI","method":"POST","payload":{"id":"FTI","counts":[{"accountId":""+str(folderId)+"","unseen":0}]}}],"responseType":"json"}
                    status, response = self.run_requests(_linkApi, action='POST', data=json.dumps(_payload),proxies=self.proxies,allow_redirects=True,verify=False)
                    if not status:
                        logging.warning(f"[{self.email}] get_messages requests failed! ({response})")
                        break

                    if response.status_code == 200:
                        my_result = json.loads(response.content)

                        if "error" in my_result and my_result["error"] is not None:
                            logging.warning(f"[{self.email}] Load {fld} messages failed , error code  ({my_result['error']['code']})")
                            break

                        logging.info(f"[{self.email}] Retrieve {fld} messages progress {_start}/{_total}")
                        GetMessageGroupList = my_result['result']['responses'][1]['response'] if my_result['result']['responses'][1]['id'] == "GetMessageGroupList" else my_result['result']['responses'][0]['response']
                        cnvItems = GetMessageGroupList['result']['messages']

                        for msg in cnvItems:
                            messageInfo = msg['headers']
                            if 'subject' not in messageInfo or 'internalDate' not in messageInfo: continue

                            subject = messageInfo['subject']
                            recievedDate = float(messageInfo['internalDate']) 
                            formated_date = datetime.datetime.utcfromtimestamp(recievedDate).strftime('%Y-%m-%d')   
                            if dateParam >  formated_date:
                                exitWhile=True
                                break
                            else:
                                if subjectParam == '.*' or subjectParam.lower() in subject.lower():
                                    mid = msg['id']    
                                    cid = msg['conversationId']
                                    isRead = msg['flags']['read'] if "read" in msg['flags'] else False
                                    isFlagged = msg['flags']['flagged'] if "flagged" in msg else False       
                                    Item={
                                            'cid':cid,
                                            'mid':mid,
                                            'recievedDate':formated_date,
                                            'from':messageInfo['from'][0],
                                            'isRead':isRead,
                                            "isFlagged":isFlagged,
                                            'subject': subject
                                    }  
                                    self.messages.append(Item)

                        _start+=_perPage
                        if _start>_total:break    

                    else:
                        logging.warning(f"[{self.email}] Failed to get {fld} messages  with status({respone.status_code}) !")
                        break
                    
                logging.info(f"[{self.email}] success total {fld} messages matched founds : {len(self.messages)}")
            except Exception as e:
                logging.warning(f"[{self.email}] Failed to get {fld} messages  with exception({e}) !")

    def read_messages(self,fld,date,subject):
        """ open defined mainbox message """
        read = 0
        self.session.headers.update({"Accept":"application/json",})
        self.get_messages(fld,date,subject)
        read = 0
        unread = len(self.messages)
        try:
            if unread > 0:
                for message in self.messages:
                    if not message['isRead']:
                        _linkApi = f"https://mail.yahoo.com/ws/v3/batch?name=messages.readFlagUpdate&hash={self.hash_generator()}&appId=YMailNorrin&ymreqid={self.fresh_yquid()}&wssid={self.wssid}"
                        payload = '{"requests":[{"id":"UnifiedUpdateMessage_0","uri":"/ws/v3/mailboxes/@.id=='+self.V3MailboxId+'/messages/@.select==q?q=id%3A('+message['mid']+')","method":"POST","payloadType":"embedded","payload":{"message":{"flags":{"read":true}}}}],"responseType":"json"}'        

                        status, response = self.run_requests(_linkApi, action='POST', headers=self.session.headers,data=payload, allow_redirects=True,verify=False,proxies=self.proxies)
                        if not status:
                            logging.warning(f"[{self.email}] read_messages requests failed! ({response})")
                            return read,unread
                        
                        if response.status_code == 200:
                            read += 1
                            logging.info(f"[{self.email}] {fld} read process .. {read}")
                        else:
                            logging.warning(f"[{self.email}] {fld} read failed {response.status_code} !"%(self.email,fld,response.status_code))

            logging.info(f"[{self.email}] Done! total Read {fld}: {read}/{unread}")
        except Exception as e:
            logging.warning(f"[{self.email}] {fld} read failed  {e} !")

        return read,unread

    def open_messages(self,fld,date,subject):
        """ open defined mainbox message """

        self.session.headers.update({
                        'Content-Type':'application/json',
                        'Connection':'keep-alive',
                        'Accept':'application/json, multipart/form-data',
        })
        self.get_messages(fld,date,subject)
        opened = 0
        total = len(self.messages)
        try:
            if total> 0:
                for message in self.messages:
                    url = f"https://mail.yahoo.com/ws/v3/batch?name=messages.readFlagUpdate&hash={self.hash_generator(7)}&appId=YMailNorrin&ymreqid={self.fresh_yquid()}&wssid={self.wssid}"
                    payloadOpen= '{"requests":[{"id":"UnifiedUpdateMessage_0","uri":"/ws/v3/mailboxes/@.id=='+self.V3MailboxId+'/messages/@.select==q?q=id%3A('+message['mid']+')","method":"POST","payloadType":"embedded","payload":{"message":{"flags":{"read":true}}}}],"responseType":"json"}'

                    status, response =  self.run_requests(url, action='POST', data=payloadOpen,proxies=self.proxies,allow_redirects=True,verify=False)   
                    if not status:
                        logging.warning(f"[{self.email}] open_messages requests failed! ({response})")
                        return opened, total 

                    if response.status_code == 200:
                        opened += 1
                        logging.info(f"[{self.email}] {fld} Open process .. {opened}")
                    else:
                        logging.warning(f"[{self.email}] {fld} Open failed {response.status_code} !")

            logging.info(f"[{self.email}] Done! total Open {fld}: {opened}/{total}")
        except Exception as e:
            logging.warning(f"[{self.email}] {fld} Open failed {e}!")

        return opened, total     

    def read_inbox(self,subject,date):
        logging.info(f"[{self.email}] Start action Read Inbox . . .")
        return self.read_messages('Inbox', date ,subject)

    def open_inbox(self,subject,date):
        logging.info(f"[{self.email}] Start action Open Inbox . . .")
        return self.open_messages('Inbox',date,subject)

    def read_spam(self,subject,date):
        logging.info(f"[{self.email}] Start action Read Spam . . .")
        return self.read_messages('Bulk',date,subject) 

    def open_spam(self,subject,date):
        logging.info(f"[{self.email}] Start action Open Spam . . .")
        return self.open_messages('Bulk',date,subject)

    def not_spam(self,subject,date):

        logging.info(f"[{self.email}] Start action Not Spam . . .")
        self.get_messages('Bulk',date,subject)
        marked = 0
        total = len(self.messages)
        try:
            if total > 0:
                for message in self.messages:
                    _linkApi = f"https://mail.yahoo.com/ws/v3/batch?name=messages.UnifiedUpdate&hash={self.hash_generator()}&appId=YMailNorrin&ymreqid={self.fresh_yquid()}&wssid={self.wssid}"
                    payload = '{"requests":[{"id":"UnifiedUpdateMessage_0","uri":"/ws/v3/mailboxes/@.id=='+self.V3MailboxId+'/messages/@.select==q?q=id%3A('+message['mid']+')","method":"POST","payloadType":"embedded","payload":{"message":{"flags":{"spam":false}, "folder":{"id":"'+self._YUI_BOXES['Inbox']['id']+'"}}}}],"responseType":"json"}'                    

                    status, response = self.run_requests(_linkApi, action='POST', data=payload, allow_redirects=True,verify=False,proxies=self.proxies)
                    if not status:
                        logging.warning(f"[{self.email}] not_spam requests failed! ({response})")
                        return marked,total

                    if response.status_code == 200:
                        marked += 1
                        logging.info(f"[{self.email}] not spam process .. {marked}")
                    else:
                        logging.warning(f"[{self.email}] not spam failed {response.status_code} !")
            
            logging.info(f"[{self.email}] Done! total Not Spam : {marked}/{total}")
        except Exception as e:
            logging.warning(f"[{self.email}] not spam failed {e} !")

        return marked,total
        
    def mark_flagged_messages(self,fld,date,subject):

        self.get_messages(fld,date,subject)
        flagged = 0
        total = len(self.messages)
        try:
            if total> 0:
                for message in self.messages:
                    url = f"https://mail.yahoo.com/ws/v3/batch?name=messages.UnifiedUpdate&hash={self.hash_generator()}&appId=YMailNorrin&ymreqid={self.fresh_yquid()}&wssid={self.wssid}"
                    payload = '{"requests":[{"id":"UnifiedUpdateMessage_0","uri":"/ws/v3/mailboxes/@.id=='+self.V3MailboxId+'/messages/@.select==q?q=id%3A('+message['mid']+')","method":"POST","payloadType":"embedded","payload":{"message":{"flags":{"flagged":true}}}}],"responseType":"json"}'
                    
                    status, response = self.run_requests(url,action='POST', data=payload, allow_redirects=True,verify=False,proxies=self.proxies)
                    if not status:
                        logging.warning(f"[{self.email}] mark_flagged_messages requests failed! ({response})")
                        return marked,total

                    if response.status_code == 200:
                        flagged += 1
                        logging.info(f"[{self.email}] {fld} mark flagged process .. {flagged}")
                    else:
                        logging.warning(f"[{self.email}] {fld} mark flagged failed {respone.status_code} !")
                            
            logging.info(f"[{self.email}] Done! total {fld} Mark Flagged : {flagged}/{total}")
        except Exception as e:
            logging.warning(f"[{self.email}] {fld} mark flagged failed {e} !")

        return flagged,total

    def mark_flagged_inbox(self,subject,date):
        logging.info(f"[{self.email}] Start action Mark star inbox . . .")
        return self.mark_flagged_messages('Inbox',date,subject)

    def mark_flagged_junk(self,subject,date):
        logging.info(f"[{self.email}] Start action Mark star spam . . .")
        return self.mark_flagged_messages('Bulk',date,subject) 

    def get_exists_contacts(self):
        try:
            url = 'https://mail.yahoo.com/b/contacts'
            status, response = self.run_requests(url, headers=self.session.headers, allow_redirects=True,verify=False,proxies=self.proxies)
            if not status:
                logging.warning(f"[{self.email}] get_exists_contacts requests failed! ({response})")
                return False

            if response.status_code == 200:
                # getting crumb
                posted_data = self.Get_PayLoad(response.content)
                if posted_data:
                    self.crumb = posted_data['crumb']
                # getting contacts
                html = BeautifulSoup(response.text)
                results =  html.find_all("td", attrs={'class':'J_x mq_N o_h G_e P_3gIMd V_M s_dmf'})
                for contact in results:
                    self.existsContacts.append(contact.attrs['title'])
                return True
                
            else:
                logging.warning(f"[{self.email}] failed to get exists contacts {response.status_code} !")
        except Exception as e:
            logging.warning(f"[{self.email}] failed to get exists contacts {e} !")
        return False
            
    def add_contact_directly(self,contact):

        logging.info(f"[{self.email}] Start action Add contact directly. . .")
        # get exists contacts
        added = 0
        status = self.get_exists_contacts()
        if not status:
            logging.warning(f'{self.email} failed to get exists contacts!')
        elif contact not in self.existsContacts:
            # add contact
            url = 'https://mail.yahoo.com/b/contacts'
            self.session.headers.update({
                "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language":"en-US,en;q=0.5",
                "Accept-Encoding":"gzip, deflate",
                'Content-Type':'application/x-www-form-urlencoded',
            })
            payload = {
                'CONTACTS_REVISION': '0',
                'crumb': self.crumb,
                'action':'createContact',
                'CONTACT_ID': '',
                'OLD_CONTACT': '{}',
                'contact[name_][givenName]': '',
                'contact[name_][middleName]': '',
                'contact[name_][familyName]': '',
                'contact[email_]': contact,
                'contact[nickname_]': '',
                ' contact[phone_]': '',
            }

            status, response = self.run_requests(url, action='POST', data=payload, allow_redirects=True,verify=False,proxies=self.proxies)
            if not status:
                logging.warning(f"[{self.email}] add_contact_directly requests failed! ({response})")
                return added,1

            if response.status_code == 200:
                added += 1
                self.existsContacts.append(contact)
                logging.info(f"[{self.email}] add contact directly process .. {added}")
            else:
                logging.warning(f"[{self.email}] add contact directly failed {response.status_code} !")

        else:
            # added += 1
            logging.info(f"[{self.email}] contact already exists")
        
        return added,1

    def add_contacts_inbox(self,subject,date):
        logging.info(f"[{self.email}] Start action Add contacts . . .")
        self.get_messages('Inbox',date,subject)
        added = 0
        total = len(self.messages) 
        if total > 0:
            for message in self.messages:
                contact = str(message['from']['email'].lower())
                add, count = self.add_contact_directly(contact)
                added+=add
        
        logging.info(f"[{self.email}] Done! total New Contacts added : {added}/{total}")

        return added,total
             
    def reply_message(self,subject,date,text):

        logging.info(f"[{self.email}] Start action Reply message . . .")
        self.get_messages('Inbox',date,subject)
        replied = 0
        total = len(self.messages)
        folderId = str(self._YUI_BOXES['Draft']['id'])

        if total > 0:
            for message in self.messages:
                mid  = message['mid']
                to=['{"name": "%s", "email": "%s"}'%(message["from"]['name'],message["from"]['email'])]
                to=str(",".join(to))
                body = json.dumps(re.sub("\n", "<br/>", text.strip()))
                csid = str(int(time.time()))
                subject = message['subject']
                try:   subject=subject.decode('ascii', 'ignore')
                except:
                    try:   subject=subject.encode('ascii', 'ignore').decode('ascii')
                    except:
                        subject = ''

                headers_rep ={
                          'Accept': 'application/json',
                          'Accept-Encoding': 'gzip, deflate, br',
                          'Accept-Language':'en-US,en;q=0.5',
                          'User-Agent':self.UserAgent,
                          'Content-Type': 'application/json',
                          'Connection':  'keep-alive',
                        }
                
                urlRepl1 = f"https://mail.yahoo.com/ws/v3/batch?name=messages.autoSaveV3&hash={self.hash_generator(7)}&appId=YMailNorrin&ymreqid={self.fresh_yquid()}&wssid={self.wssid}"
            
                payload_json1 = '{"requests":[{"id":"SaveMessage","uri":"/ws/v3/mailboxes/@.id=='+self.V3MailboxId+'/messages?uploadCount=0&totalAttachments=0","method":"POST","payloadType":"multipart","payloadParts":[{"partName":"jsonString","contentType":"application/json","payload":{"actions":{"responseMessage":true},"message":{"csid":"'+csid+'","newMessage":false,"headers":{"subject":"Re: '+subject+'","from":[{"name":"'+self.email+'","email":"'+self.email+'"}],"replyTo":[],"to":['+to+'],"cc":[],"bcc":[]},"folder":{"id":"'+folderId+'"},"flags":{"spam":"false","read":"true"},"inReplyTo":{"messageReference":{"id":"'+mid+'"},"replied":true,"forwarded":false}},"simpleBody":{"attachments":[],"html":'+body+'}}}],"filters":{"select":{"cid":"$..message.conversationId"}}}],"responseType":"json"}'
                
                status, response_D = self.run_requests(urlRepl1, action='POST', data=payload_json1, headers=headers_rep, proxies=self.proxies, allow_redirects=True, verify=False)
                if not status:
                    logging.warning(f"[{self.email}] reply_message requests failed! ({response_D})")
                    break

                if response_D.status_code == 200:
                    try:
                        detailJSON = response_D.json()
                        id_d = detailJSON['result']['responses'][0]['response']['result']['message']['id']

                        urlSend2 =f"https://mail.yahoo.com/ws/v3/batch?name=messages.send&hash={self.hash_generator()}&appId=YMailNorrin&ymreqid={self.fresh_yquid()}&wssid={self.wssid}"
                        payload_json2 = '{"requests":[{"id":"SendMessage","uri":"/ws/v3/mailboxes/@.id=='+self.V3MailboxId+'/messages/@.id=='+id_d+'/send","method":"POST","payloadType":"embedded","payload":{"csid":"'+csid+'","destinationFolder":{"id":"2"}},"requests":[{"id":"UpdateMessages","uri":"/ws/v3/mailboxes/@.id=='+self.V3MailboxId+'/messages/@.select==q?q=id%3A('+mid+')&async=true","method":"POST","payloadType":"embedded","payload":{"message":{"flags":{"answered":true,"forwarded":false}}}}]}],"responseType":"json"}'
                        
                        response_S = self.session.post(urlSend2, data=payload_json2, headers=headers_rep, proxies=self.proxies, allow_redirects=True, verify=False)
                        if response_S.status_code == 200:
                            try:
                                detailJSON = response_S.json()
                                if detailJSON['error'] is None:
                                    replied+=1
                                    logging.info(f"[{self.email}] reply message process .. {replied}")
                            except Exception as e:
                                logging.warning(f"[{self.email}] reply message exception 2: {e}")
                                break
                        else:
                            logging.warning(f"[{self.email}] reply message step 2 failed to get compose form {response_D.status_code} !")

                    except Exception as e:
                        logging.warning(f"[{self.email}] reply message exception: {e}")
                        break
                else:
                    logging.warning(f"[{self.email}] reply message failed to get compose form {response_D.status_code} !")

        logging.info(f"[{self.email}] Done! total Reply message : {replied}/{total}")

        return replied,total
   
    def empty_spam_folder(self,subject,date) :
        
        logging.info(f"[{self.email}] Start action Empty Spam Folder . . .")
        self.get_messages('Bulk',date,subject)
        marked = 0
        total = len(self.messages)
        
        try:
            if total > 0:
                for message in self.messages:
                    
                    # message_date = datetime.datetime.fromtimestamp(int(message['recievedDate']))
                    message_date = datetime.datetime.fromtimestamp(int(message['recievedDate']) / 1000)
                    _linkApi = f"https://mail.yahoo.com/ws/v3/batch?name=messages.UnifiedUpdate&hash={self.hash_generator()}&appId=YMailNorrin&ymreqid={self.fresh_yquid()}&wssid={self.wssid}"    
                    payload = '{"requests":[{"id":"UnifiedUpdateMessage_0","uri":"/ws/v3/mailboxes/@.id=='+self.V3MailboxId+'/messages/@.select==q?q=id%3A('+message['mid']+')","method":"POST","payloadType":"embedded","payload":{"message":{"flags":{"spam":false},"folder":{"id":"4"}}}}],"responseType":"json"}'  
                    if message_date.date() == date_mail:
                        status, response = self.run_requests(_linkApi, action='POST', data=payload, allow_redirects=True,verify=False,proxies=self.proxies)
                        if not status:
                            logging.warning(f"[{self.email}] Empty Spam Folder requests failed! ({response})")
                            return marked,total

                        if response.status_code == 200:
                            marked += 1
                            logging.info(f"[{self.email}] Empty Spam Folder process .. {marked}")
                        else:
                            logging.warning(f"[{self.email}] Empty Spam Folder failed {response.status_code} !")
            
            logging.info(f"[{self.email}] Done! total Empty Spam Folder : {marked}/{total}")
        
        except Exception as e:
            logging.warning(f"[{self.email}] Empty Spam Folder failed {e} !")

        return marked,total
    
    
    

    
    

if __name__ == "__main__":
    
    start = time.time()
    
    LOG_FILENAME = "/tmp/yah_job.out"
    # logging.basicConfig(filename=LOG_FILENAME, level=logging.INFO,  filemode="a", format="%(asctime)s %(levelname)s %(message)s")
    email_reco = ""
    ag = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:107.0) Gecko/20100101 Firefox/107.0"
    (login,pw,pxy) = "ayoubehssi@yahoo.com,ofpptTdi2020,216.144.237.91".split(",")
    #ag = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:106.0) Gecko/20100101 Firefox/106.0"
    #(login,pw,pxy) = "charles.james823@yahoo.com,M6Sjb$?C9a26,141.11.36.118".split(",")
    
    #ag = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:107.0) Gecko/20100101 Firefox/107.0"
    #(login,pw,pxy) = "speranzaarcuri286@yahoo.com,FDByK3w7,102.129.188.119".split(",")
    #(login,pw,pxy) = "damianawolf246@yahoo.com,nDENN2mZ,102.129.188.121".split(",")
    #(login,pw,pxy) = "gregg_crumbley@yahoo.com,HGaZ2Y9E,102.129.188.130".split(",") 
    #(login,pw,pxy) = "manuel_russo23@yahoo.com,bQ7Vs84d,104.234.163.6".split(",") 
    #(login,pw,pxy) = "alvisa_genovese@yahoo.com,FDByK3w7,104.234.163.8".split(",") 

    yh_CNX = Yahoo(login, pw, pxy, 3128, ag, email_reco)
    print("proxy - %s"%yh_CNX.status_proxy)

    if yh_CNX.status_proxy:
        vl_return = yh_CNX.login()
        print("login - %s"%vl_return)
        if vl_return: 
            print(login,'login ok')
            subject_=".*";date_mail="2023-05-03"
            #yh_CNX.get_folders()
            #yh_CNX.get_messages('Inbox', date_mail, subject_)
            #yh_CNX.open_inbox(subject_, date_mail)
            # yh_CNX.open_spam(subject_, date_mail)
            #yh_CNX.read_inbox(subject_, date_mail)
            # yh_CNX.read_spam(subject_, date_mail)
            #yh_CNX.get_exists_contacts()
            #yh_CNX.add_contact_directly('gmhotbox@aim.com')
            #yh_CNX.reply_message(subject_, date_mail, 'aloha')
            #yh_CNX.add_contacts_inbox(subject_, date_mail)
            yh_CNX.empty_spam_folder(subject_,date_mail)
            #status = ht_CNX.get_all_contacts()
            #n,m = ht_CNX.add_contact_directly("neo_Fleming952f@outlook.com")
            #ht_CNX.GetMessages(subject_, date_mail, "junkemail") 
            
            #yh_CNX.logout()
    
    print("finished.")
    print("Elapsed Time: %s" % (time.time() - start))
