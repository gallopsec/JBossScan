#-*- coding: utf-8 -*-
import argparse,sys,requests,time,os,re
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
#fofa：title="Welcome to JBoss AS" && country!="CN"
def banner():
    test = """
       ______               
      / / __ )____  __________
 __  / / __  / __ \/ ___/ ___/
/ /_/ / /_/ / /_/ (__  |__  ) 
\____/_____/\____/____/____/                                                                                                                                                                                                                                                                                                                                                   
            tag:  JBoss POC                                       
            @author by gallopsec            
"""
    print(test)
import requests

headers = {
	"User-Agent":"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:67.0) Gecko/20100101 Firefox/67.0"
}
vuls=['/jmx-console','/web-console','/invoker/JMXInvokerServlet','/admin-console','/jbossmq-httpil/HTTPServerILServlet','/invoker/readonly']
def poc(target):
    for listt in vuls:
        listt = listt.strip()
        url = target + listt
        try:    
            r = requests.get(url, headers=headers, timeout=3, verify=False)
            #jmx-console
            #web-console
            if r.status_code == 401:
                if "jmx" in url:											
                    print ("[+]jmx-console vulnerability may exist!")
                    with open("jmx-console.txt", "a+", encoding="utf-8") as f:
                        f.write(target+"\n")
                elif "web" in url:
                    print ("[+]web-console vulnerability may exist!")
                    with open("web-console.txt", "a+", encoding="utf-8") as f:
                        f.write(target+"\n")
                else:
                    pass
            else:
                pass

            #admin-console
            #JBoss JMXInvokerServlet(CVE-2015-7501)
            #JBOSSMQ JMS(CVE-2017-7504)
            if r.status_code == 200:
                if "admin" in url:
                    print ("[+]admin-console vulnerability may exist!")
                    with open("admin-console.txt", "a+", encoding="utf-8") as f:
                        f.write(target+"\n")
                elif "JMXInvokerServlet" in url:
                    print ("[+]JBoss JMXInvokerServlet(CVE-2015-7501) vulnerability may exist!")
                    with open("CVE-2015-7501.txt", "a+", encoding="utf-8") as f:
                        f.write(target+"\n")
                elif "jbossmq" in url:
                    print ("[+]JBOSSMQ JMS(CVE-2017-7504) vulnerability may exist!")
                    with open("CVE-2017-7504.txt", "a+", encoding="utf-8") as f:
                        f.write(target+"\n")
                else:
                    pass
            else:
                pass

            #(CVE-2017-12149)
            if r.status_code == 500:
                if "readonly" in url:
                    print ("[+]CVE-2017-12149 vulnerability may exist!")
                    with open("CVE-2017-12149.txt", "a+", encoding="utf-8") as f:
                        f.write(target+"\n")
                else:
                    pass
            else:
                pass
        except Exception as e:
            pass
def main():
    banner()
    parser = argparse.ArgumentParser(description='JBoss POC')
    parser.add_argument("-u", "--url", dest="url", type=str, help=" example: http://www.example.com")
    parser.add_argument("-f", "--file", dest="file", type=str, help=" urls.txt")
    args = parser.parse_args()
    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list=[]
        with open(args.file,"r",encoding="utf-8") as f:
            for url in f.readlines():
                url_list.append(url.strip().replace("\n",""))
        mp = Pool(100)
        mp.map(poc, url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usage:\n\t python3 {sys.argv[0]} -h")

if __name__ == '__main__':
    main()