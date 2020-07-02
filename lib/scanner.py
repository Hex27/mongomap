
import sys;
import requests;
import urllib;
import urllib.parse;
import copy;
import json;

from .tester import getTests;

from util.output import info;
from util.output import failure;
from util.output import question;
from util.output import success;
from util.output import bold;
from util.output import verbose;

class Scanner():
    def __init__(self,url,method="get",data=""):
        self.url = url;
        self.method = method.lower();
        self.textBaseline = "";
        self.textErrorBaseline = "";
        self.data = data;
        self.cookies = {};
        self.headers = {};
        self.handleData();
        self.collections = [];
        
        self.element_attributes = [];
        self.objectIDs = [];
        
        self.maxthreads = 50;
        self.maxbrute = 100;
        self.tests = {};
        self.ignore_check = [];
        self.csrfToken = "";
        self.techniques = "aw";

    def getParams(self):
        params = [];
        for key in self.data:
            params.append(key);

        return params;

    def dumpData(self,param,testname):
        test = self.tests[param][testname];
        data = test.grabData();
        return data;

    def testParam(self,p):
        successes = [];
        tests = getTests(self.url,p,self);
        self.tests[p] = tests;
        for testname in tests:
            test = tests[testname];
            if str(test.getID()) in self.techniques or str(test.getType()) in self.techniques:
                info("Attempting " + testname);
                if test.vulnTest():
                    success(p+" is "+testname+" injectable!");
                    successes.append(testname);
            else:
                verbose("Skipping test " + testname);
        return successes;

    def handleCSRF(self,data): #To be changed whenever.
        session = requests.Session();
        if self.csrfToken == "":
            return session;
        r = session.get(self.url);
        aStart = r.text.find('name="' + self.csrfToken + '" value="');
        token = r.text[aStart+24:aStart+56]
        data[self.csrfToken] = token;
        return session;


    def sendData(self,data):
        
        session = self.handleCSRF(data);
        req = None;
        #print(data);
        if self.method == "get":
            data = copy.deepcopy(data);
            for param in data:
                data[param] = urllib.parse.quote(data[param]);
            strData = self.implodeData(data);
            req = session.get(self.url + "?" + strData,headers=self.headers,cookies=self.cookies,allow_redirects=False);
        elif self.method == "post":
            req = session.post(self.url,data,headers=self.headers,cookies=self.cookies,allow_redirects=False);
        elif self.method == "json":
            #print("DEBUG:",data);
            req = session.post(self.url, json=data);
        
        return req;
                
    def check(self,req):
        if req.status_code != self.status_baseline:
            if "status" not in self.ignore_check:
                return "status";
        if req.url.split("?")[0] != self.url:
            if "url" not in self.ignore_check:
                return "url";
        if req.text != self.textBaseline:
            if "text" not in self.ignore_check:
                return "text";
        return "none";
        
    def handleData(self):
        strData = self.data;
        if self.method == "get" and strData == "":
            split = self.url.split("?");
            if len(split) != 2:
                failure("Get request method selected, but url has no get parameters");
                sys.exit(1);
            else:
                self.explodeData(split[1]);
                self.url = split[0];
        elif self.method == "post":
            self.explodeData(strData);
        elif self.method == "json":
            pass; #Already in the correct form.
        
        if "/" not in self.url.replace("://",""):
            bold("URL: " + self.url);
            if question("There is no / in your url. Do you want to add a trailing slash?"):
                self.url += "/";

    def explodeData(self,string):
        data = {};
        sent = string.split("&");
        for keyval in sent:
            explode = keyval.split("=");
            if len(explode) != 2:
                data[keyval] = "";
            else:
                data[explode[0]] = explode[1];
        self.data = data;

    def implodeData(self,data):
        if self.method == "json":
            return json.dumps(data); #For printing purposes.
        stringData = "";
        for key in data:
            stringData += key + "=" + data[key] + "&";
        return stringData[:-1];

    def testConnection(self):
        #try:
            req = self.sendData(self.data);
            self.status_baseline = req.status_code;
            if str(req.status_code).startswith("4"):
                failure("Website returned status code "+str(req.status_code)+"!");
            
            self.textBaseline = req.text;
            
            if str(req.status_code).startswith("3"):
                if question("Redirect to " + req.url + " detected. Follow?"):
                    self.url = req.url;
                    return self.testConnection();
                    
            return True;
        #except Exception as err:
            #print(err);
            #return False;
        
