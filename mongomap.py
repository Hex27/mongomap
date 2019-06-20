import sys;

from lib.argextractor import extractArgs;
from lib.argextractor import initScanner;
from lib.scanner import Scanner;

from util.output import info;
from util.output import verbose;
from util.output import success;
from util.output import bold;
from util.output import failure;
from util.output import question;
from util.output import yellow;
from util.output import setVerbose;
from util.output import colinit;


def banner():
    file = open("banner.txt","r",encoding="utf-8");
    banner = file.read().strip().split("\n");
    file.close();
    for line in banner:
        yellow(line);

    bold("v1.0.0");

def main():
    colinit();
    banner();
    #Initiations
    parsed = extractArgs();
    scanner = initScanner(parsed);


    #Test connection to target
    if scanner.testConnection():
        success("URL can be reached.");
    else:
        failure(scanner.url+" cannot be reached. Did you forget http://?");
        sys.exit(1);

    print()
    
    params = scanner.getParams();

    if "v" in parsed:
        setVerbose(True);
    
    if "p" in parsed:
        toTest = parsed["p"].split(",");
        for param in toTest:
            if param not in params:
                failure("Param, " + param + " is not provided in your get/post data!");
                sys.exit(1);
        params = toTest;    

    verbose("Going to test the following parameters:");
    for param in params:
        verbose(param);

    print()
    
    bold("Beginning testing phase.");
    vulnParams = {};
    tested = 0;
    for param in params:
        tested += 1;
        bold("Testing for param "+param);
        successes = scanner.testParam(param);
        if len(successes) > 0:
            vulnParams[param] = successes;
            success(param + " is injectible.");
            if tested < len(params):
                if not question("Continue testing other parameters?"):
                    break;

    print()
    bold("Test phase completed.");

    if len(vulnParams) == 0:
        failure("No vulnerable parameters found.");
        sys.exit(1);

    print()
    success("Vulnerable Parameters:");
    for param in vulnParams:
        success(param);
        for vuln in vulnParams[param]:
            success("- " + vuln);

    print()
    info("Attempting to dump data...");

    for param in vulnParams:
        bold("Parameter: " + param);
        for vuln in vulnParams[param]:
            print()
            bold("Attemping dump with " + vuln + " on param " + param);
            print()
            dump = scanner.dumpData(param,vuln);
            if dump == None:
                print()
                failure(vuln + " for " + param + " failed to dump.");
            else:
                print()
                success(vuln + " for " + param + " has retrieved:");
                if type(dump) == type("str"):
                    success("\t"+dump);
                elif type(dump) == type({}):
                    for key in dump:
                        success("\t"+str(key) + " : " + str(dump[key]));
                elif type(dump) == type([]):
                    for i in dump:
                        success("\t"+str(i));
            print()
    

main();
