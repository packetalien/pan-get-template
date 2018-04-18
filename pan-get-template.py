#!/usr/bin/env python
# ========================================================================
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
# ========================================================================
# Requests library is not standard and
# may require extra install.
# Run the following at a command prompt (linux/macOS)
# ========================================================================
# pip install requests
# ========================================================================
# This script is designed to interact with Panorama
# This script is in an alpha state and your miliage may vary
# Scripting can sometimes seem like a pain in the ^&&, so this one has
# some humor in it. If you do not like it, change it, contribute, edit,
# and make this your own!

__author__ = "Richard Porter (@packetalien)"
__copyright__ = "Copyright 2018, Palo Alto Networks"
__version__ = "0.1"
__license__ = "GPL"
__status__ = "Development"


try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    raise ValueError('requests support not available, please install module')
import xml.etree.ElementTree as ET
import re

# Base User Input Functions


def getfwipfqdn():
    while True:
        try:
            fwipraw = raw_input("Please enter an IP or FQDN: ")
            ipr = re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", fwipraw)
            fqdnr = re.match(r"(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)", fwipraw)
            print("You entered %s\n" % fwipraw)
            if ipr:
                print("You entered and IPv4 address....")
                break
            elif fqdnr:
                print("You entered what seems to be an FQDN .... Kidding, we checked, keep going!")
                break
            else:
                print("There was something wrong with your entry. Please try again.\n")
        except:
            print("Woops, we just threw an exception. There was some kind of problem entering your IP or FQDN. The script will probably exit and create frustration.\n")
    return fwipraw


def getpass():
    while True:
        try:
            password = raw_input("Please enter your password: ")
            passwordr = re.match(r"^.{5,50}$",password) # simple validate PANOS has no password characterset restrictions
            if passwordr:
                print("Hey, the script got your password, level up to next phase. And we don't cache or keep it \n")
                break
            else:
                print("There was something wrong with your entry. Please try again.\n")
        except:
            print("Woops, we just threw an exception. There was some kind of problem entering your password. Please try not to throw the cookies across the room? They are good!\n")
    return password


def getuname():
    while True:
        try:
            username = raw_input("Please enter a user name (note, must have API access): ")
            usernamer = re.match(r"^[a-z0-9_-]{3,24}$", username) # 3 - 24 characters {3,24}
            print("You entered %s" % username)
            if usernamer:
                print("Valid captured, this script is moving on!\n")
                break
            else:
                print("There was something wrong with your entry. Please try again.\n")
            print("You entered %s\n" % username)
        except:
            print("Woops, we just threw an exception. There was some kind of problem entering your user name. This is a little embarrasing, but only a little :)...\n")
    return username

def gettemplatename():
    while True:
        try:
            templatename = raw_input("Please enter a template name: ")
            templatenamer = re.match(r"^.{5,32}$", templatename) # basic check for 5-32 characters
            print("You entered %s" % templatename)
            if templatenamer:
                break
            else:
                print("There was something wrong with your entry. Please try again.\n")
            print("You entered %s\n" % username)
        except:
            print("Woops, we just threw an exception. There was some kind of problem entering your template name. This is a little embarrasing, but only a little :)...\n")
    return templatename


def getkey(fwip):
    try:
        fwipgetkey = fwip
        username = getuname()
        password = getpass()
        keycall = "https://%s/api/?type=keygen&user=%s&password=%s" % (fwipgetkey,username,password)
        r = requests.get(keycall, verify=False)
        tree = ET.fromstring(r.text)
        if tree.get('status') == "success":
            apikey = tree[0][0].text
    except requests.exceptions.ConnectionError as e:
        print("Woops, we just threw an exception. There was a problem connecting to the firewall. Please check the connection information and try again.")
    return apikey

#/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='%s']


def gettemplate(passkey,fwip,templatename):
    try:
        type = "config"
        action = "get"
        fwkey = passkey
        fwipl = fwip
        template = templatename
        xpath = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='%s']" % (template)
        call = "https://%s/api/?type=%s&action=%s&xpath=%s&key=%s" % (fwipl, type, action, xpath, fwkey)
        r = requests.get(call, verify=False)
        tree = ET.fromstring(r.text)
        return r.text
    except requests.exceptions.ConnectionError as e:
        print("There was a problem in getting your policies. \n Please vent frustrations in a safe manner and throw a candy bar at the wall! \n If this is helpful the error was captured as: " + e)


def main():
    try:
        fwip = getfwipfqdn()
        mainkey = getkey(fwip)
        templatename = gettemplatename()
        results = gettemplate(mainkey,fwip,templatename)
        print(results)
        #print(results.text)
    except:
        print("Something happened and your output didn't.")


if __name__ == "__main__":
    main()
