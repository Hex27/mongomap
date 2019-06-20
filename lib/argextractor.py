
import sys;
from .scanner import Scanner;

from util.output import info;
from util.output import verbose;
from util.output import success;
from util.output import failure;
from util.output import plain;
from util.output import bold;
from util.output import yellow;
from .tester import getTests;

def showHelp():
    bold("Usage: mongomap -u [url] ...");
    plain("");
    plain("-u"+"\t\t"+"Refers to the URL of the target. Includes port and get parameters if you are using get requests.");
    plain("--method"+"\t"+"Set to either \"post\" or \"get\". By default, this will be set to \"get\"");
    plain("--data"+"\t"+"If you are using post requests, use this option to specify post data");
    plain("");
    bold("--Flexibility--");
    plain("--cookies"+"\t"+"Set cookies to send. Separate different cookies with &");
    plain("--headers"+"\t"+"Specifies a header to send. Separate different headers with ;");
    plain("--maxbrute"+"\t"+"Default value is 100. This is the maximum number of bruteforce attempts the program will try. Set to 0 for limitless.");
    plain("--maxthreads"+"\t"+"Default value is 50. This is the maximum number of concurent threads the program will spawn.");
    plain("--csrftoken"+"\t"+"Specify the csrftoken to be checked for. You must modify code for this option to work.");
    plain("--ignorecheck"+"\t"+"Ignore a certain check. Set these when false positives are found. Can be set to the following.");
    plain("");
    plain("\t" + "text --- Ignore website content comparisons. Useful for combatting CSRF.");
    plain("\t" + "status --- Ignore status code comparison");
    plain("\t" + "url --- Ignore redirect URL comparison");
    plain("");
    plain("--maxthreads"+"\t"+"Default value is 50. This is the maximum number of concurent threads the program will spawn.");
    plain("-t"+"\t"+"Specify some technique IDs to use.");
    plain("");
    bold("--Post-Detection--");
    plain("--dump" + "\t" + "Attempts to retrieve as much information as possible via detected injection methods. If no other post-detection options are used, dump will be used by default.");
    #plain("--objectids" + "\t" + "Specify a list of objectIDs to try to grab data from. Separate with commas.");
    plain("");
    bold("--Help and Documentation--");
    plain("-h --help" + "\t" + "Shows this help page. Use with -t to display documentation regarding the specified techniques");
    plain("-ts --techniques" + "\t" + "Display all techniques.");
    plain("");
    bold("--Examples--");
    bold("mongomap -u http://challenger.com?sad=22");
    bold("mongomap -u http://localhost:2222?search=1 -t 324");
    bold("mongomap -u http://localhost:2222?search=1 -t w");
    bold("mongomap -u http://192.168.1.321 --method post --data \"username=hi&password=letmein\"");
    bold("mongomap -u https://target.com:1231?foo=1 --cookies \"PHPSESSID=1242345234512345&ID=123\"");
    bold("mongomap -u http://10.10.10.123 --method post --data search=1 --headers \"Host: administrator1.friendzone.red; User-Agent: imlazytotypethis\"");
    plain("");
    

def showTechniques():
    plain("");
    bold("--Techniques--");
    plain("");
    tests = getTests("","",Scanner("http://localhost/index.php?me=a"));
    print(" %-5s|%-6s|%-20s"%("ID","Type","Name"));
    print("_"*50);
    for testname in tests:
        test = tests[testname];
        print(" %-5d|%-6s|%-20s"%(test.getID(),test.getType(),testname));
    plain("");
    bold("Use the -t command with -h to show help regarding each technique.");
        
def showTechniqueHelp(techniques):
    tests = getTests("","",Scanner("http://localhost/index.php?me=a"));
    for testname in tests:
        test = tests[testname];
        if str(test.getID()) in techniques or str(test.getType()) in techniques:
            plain("");
            success(testname);
            print("_"*50);
            failure("ID: " + str(test.getID()));
            type = "(a) Array Injection";
            if test.getType() == "w":
                type = "(w) Where Injection";
            if "blind" in testname.lower():
                type = "Blind " + type;
                
            failure("Type: " + type);
            plain("");
            test.doc();
            print("_"*50);
    
def extractArgs():
    flags = ["dump","help","h","v","techniques","ts"];
    options = ["u","t","method","data","p","cookies","headers","maxbrute","maxthreads","ignorecheck","csrftoken","objectids"];

    parsed = {};

    if len(sys.argv) <= 1:
        showHelp();
        sys.exit(1);

    expectingVal = None;

    #Parse arguments
    for arg in range(1,len(sys.argv)):
        arg = sys.argv[arg];
        if expectingVal == None:
            if arg.startswith("-"):
                arg = arg.replace("-","");
                if arg in flags:
                    parsed[arg] = True;
                elif arg in options:
                    expectingVal = arg;
                else:
                    failure("Unknown option/flag: "+arg);
                    sys.exit(1);
            else:
                failure("Value without option: "+arg);
                sys.exit(1);
        else:
            if arg.startswith("-"):
                failure("Expecting value for option: "+expectingVal);
                sys.exit(1);
            else:
                parsed[expectingVal] = arg;
                expectingVal = None;               

    
    verbose("Options provided:");
    for key in parsed:
        if key in flags:
            verbose(key+" flag");
        else:
            verbose(key+" - "+parsed[key]);
    
    if "techniques" in parsed or "ts" in parsed:
        showTechniques();
        sys.exit(1);
    
    if "h" in parsed or "help" in parsed:
        if "t" not in parsed:
            showHelp();
        else:
            techniques = parsed["t"];
            showTechniqueHelp(techniques);
        sys.exit(1);

    if "u" not in parsed:
        failure("You must specify a target with -u!");
        sys.exit(1);


    return parsed;

def initScanner(parsed):
    url = parsed["u"];
    method = "get";
    data = "";
    if "method" in parsed:
        if parsed["method"] == "post":
            if "data" not in parsed:
                failure("You must set the data option if you want to send post requests!");
                sys.exit(1);
        method = parsed["method"];
    if "data" in parsed:
        data = parsed["data"];
    
    scanner = Scanner(url,method,data);
    
    if "cookies" in parsed:
        cookies = {};
        for entry in parsed["cookies"].split(";"):
            key,value = entry.split("=");
            key = key.strip();
            value = value.strip();
            cookies[key] = value;
        scanner.cookies = cookies;

    if "headers" in parsed:
        headers = {};
        for entry in parsed["headers"].split(";"):
            key,value = entry.split(":");
            key = key.strip();
            value = value.strip();
            headers[key] = value;
        scanner.headers = headers;

    if "maxthreads" in parsed:
        maxthreads = int(parsed["maxthreads"]);
        scanner.maxthreads = maxthreads;
            
    if "maxbrute" in parsed:
        maxbrute = int(parsed["maxbrute"]);
        scanner.maxbrute = maxbrute;
        
    
    if "objectids" in parsed:
        objectids = parsed["objectids"].split(",");
        scanner.objectIDs = objectids;
        
    if "csrftoken" in parsed:
        csrftoken = parsed["csrftoken"];
        failure("Warning: CSRFToken handling is not coded yet. You must modify handleCSRF inside lib/scanner.py to let it work with a specific situation.");
        scanner.csrfToken = csrftoken;
        
    if "ignorecheck" in parsed:
        scanner.ignore_check = parsed["ignorecheck"].split(",");
        
    if "t" in parsed:
        scanner.techniques = parsed["t"];
        
        
    return scanner;


