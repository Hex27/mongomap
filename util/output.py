from colorama import Fore;
from colorama import Style;
import colorama;

verb = False;

def colinit():
    colorama.init();

def setVerbose(setting):
    global verb;
    verb = setting;

def verbose(message):
    global verb;
    if verb:
        print(Style.BRIGHT+Fore.BLUE+"[v] "+message+Style.NORMAL+Fore.RESET);

def plain(message):
    print("    " + message); 

def success(message):
    print(Style.BRIGHT+Fore.GREEN+"[+] "+message+Style.NORMAL+Fore.RESET);

def yellow(message):
    print(Style.BRIGHT+Fore.YELLOW+message+Style.NORMAL+Fore.RESET);

def bold(message):
    print(Fore.CYAN+"[*] "+message+Fore.RESET);

def failure(message):
    print(Style.BRIGHT+Fore.RED+"[-] "+message+Style.NORMAL+Fore.RESET);

def info(message):
    print(Fore.MAGENTA+"[i] "+message+Fore.RESET);


def question(message):
    print(Fore.YELLOW,end="");
    text = input("[?] "+message+" [y/N] ").lower();
    print(Fore.RESET,end="");
    if text == "n" or text == "no":
        return False;
    return True;
    
