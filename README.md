# Mongomap

Mongomap is a penetration-testing tool inspired by SQLMap, made specifically for MongoDB Injection on web applications. 

## Why make this when [nosqlmap](https://github.com/codingo/NoSQLMap) is a thing?
That other project seems to be centric on detecting the presence of noSQL injection, instead of actually exploiting the vulnerability. It also has a wide range of targets, including open DB ports. MongoMap, however, primarily aims to exploit MongoDB Injection to retrieve data from web applications.

## Why only MongoDB and why is it not very efficient on large volumes of data?
Because I initially made it for a CTF challenge. 

However, I am open to supporting more DB backends, and making my code more efficient, I'd just need some time to actually get down to doing it.

## Installation
As of now, Mongomap as 2 dependencies:
requests
colorama

You can use the package manager [pip](https://pip.pypa.io/en/stable/) to install these libraries.

```bash
pip install requests
pip install colorama
```

As an additional note, Mongomap is made with python3

## Usage

This command will display MongoMap's various arguments and syntaxes
```bash
python3 mongomap.py 
```

```
╔═╗╔═╗╔═══╗╔═╗─╔╗╔═══╗╔═══╗╔═╗╔═╗╔═══╗╔═══╗
║║╚╝║║║╔═╗║║║╚╗║║║╔═╗║║╔═╗║║║╚╝║║║╔═╗║║╔═╗║
║╔╗╔╗║║║─║║║╔╗╚╝║║║─╚╝║║─║║║╔╗╔╗║║║─║║║╚═╝║
║║║║║║║║─║║║║╚╗║║║║╔═╗║║─║║║║║║║║║╚═╝║║╔══╝
║║║║║║║╚═╝║║║─║║║║╚╩═║║╚═╝║║║║║║║║╔═╗║║║───
╚╝╚╝╚╝╚═══╝╚╝─╚═╝╚═══╝╚═══╝╚╝╚╝╚╝╚╝─╚╝╚╝───
By Hex_27
[*] Usage: mongomap -u [url] ...

    -u          Refers to the URL of the target. Includes port and get parameters if you are using get requests.
    --method    Set to either "post" or "get". By default, this will be set to "get"
    --data      If you are using post requests, use this option to specify post data

[*] --Flexibility--
    --cookies   Set cookies to send. Separate different cookies with &
    --headers   Specifies a header to send. Separate different headers with ;
    --maxbrute  Default value is 100. This is the maximum number of bruteforce attempts the program will try. Set to 0 for limitless.
    --maxthreads        Default value is 50. This is the maximum number of concurent threads the program will spawn.
    --csrftoken Specify the csrftoken to be checked for. You must modify code for this option to work.
    --ignorecheck       Ignore a certain check. Set these when false positives are found. Can be set to the following.

        text --- Ignore website content comparisons. Useful for combatting CSRF.
        status --- Ignore status code comparison
        url --- Ignore redirect URL comparison

    --maxthreads        Default value is 50. This is the maximum number of concurent threads the program will spawn.
    -t  Specify some technique IDs to use.

[*] --Post-Detection--
    --dump      Attempts to retrieve as much information as possible via detected injection methods. If no other post-detection options are used, dump will be used by default.

[*] --Help and Documentation--
    -h --help   Shows this help page. Use with -t to display documentation regarding the specified techniques
    -ts --techniques    Display all techniques.

[*] --Examples--
[*] mongomap -u http://challenger.com?sad=22
[*] mongomap -u http://localhost:2222?search=1 -t 324
[*] mongomap -u http://localhost:2222?search=1 -t w
[*] mongomap -u http://192.168.1.321 --method post --data "username=hi&password=letmein"
[*] mongomap -u https://target.com:1231?foo=1 --cookies "PHPSESSID=1242345234512345&ID=123"
[*] mongomap -u http://10.10.10.123 --method post --data search=1 --headers "Host: administrator1.friendzone.red; User-Agent: imlazytotypethis"
```

## What does it work against?
You can check the full description of each technique I've written to perform MongoDB Injection with this command:
```bash
python3 mongomap.py -h -t aw
```
It contains most of my documentation for those techniques. However, the basic payloads involved are:
Parsing in PHP arrays (Instead of username=a, it sends username[$ne]=a, so poorly sanitised MongoDB backends will have a different request)
Injecting WHERE requests by parsing javascript with single or double quote escapes. There's a payload for a simple where check, as well as injecting into Javascript functions.

The tool attempts to detect differences in page contents, or status code, in order to determine success in injection.
However, the difference detection mechanism is still kind of skimpy and prone to false positives, and definitely can be polished more.

## Contributing
Pull requests are welcome, though I may take a while to respond.
For major changes, please open an issue first to discuss what you would like to change.
This is one of my first public python projects, and there definitely is a lot I can improve on with this code. Do leave some tips for me if you find that I've missed something.

## License
[MIT](https://choosealicense.com/licenses/mit/)
