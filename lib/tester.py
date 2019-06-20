
import urllib.parse;
from tests.regexArrayBlindInjection import RegexArrayBlindInjection;
from tests.notEqualsArrayInjection import NotEqualsArrayInjection;
from tests.whereAlwaysTrueInjection import WhereAlwaysTrueInjection;
from tests.whereBlindJSONStringifyInjection import WhereBlindJSONStringifyInjection;
from tests.whereAlwaysTrueFunctionInjection import WhereAlwaysTrueFunctionInjection;
from tests.whereObjectIDEnumerationBlindInjection import WhereObjectIDEnumerationBlindInjection;
from tests.whereBlindFunctionJSONStringifyInjection import WhereBlindFunctionJSONStringifyInjection;

def getTests(url,param,scanner):
    tests = {\
        "Not-Equals Array (param[$ne]) Injection":NotEqualsArrayInjection(url,param,scanner),\
        "Regex Array (param[$regex]) Blind Injection":RegexArrayBlindInjection(url,param,scanner),\
        "Where Always True Function Injection":WhereAlwaysTrueFunctionInjection(url,param,scanner),\
        "Where (Function Javascript Evaluation) Blind Injection (JSONStringify)":WhereBlindFunctionJSONStringifyInjection(url,param,scanner),\
    #Deprecated. JSONStringify methods of extraction are more efficient.    #"Where ObjectID Enumeration Blind Injection":WhereObjectIDEnumerationBlindInjection(url,param,scanner),\
        "Where Always True Injection":WhereAlwaysTrueInjection(url,param,scanner),\
        "Where (Functionless String) Blind Injection (JSONStringify)":WhereBlindJSONStringifyInjection(url,param,scanner)\
    };
    return tests;
