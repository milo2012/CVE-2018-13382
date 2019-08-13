# CVE-2018-13382
CVE-2018-13382
  
https://devco.re/blog/2019/08/09/attacking-ssl-vpn-part-2-breaking-the-Fortigate-ssl-vpn/
  
An Improper Authorization vulnerability in Fortinet FortiOS 6.0.0 to 6.0.4, 5.6.0 to 5.6.8 and 5.4.1 to 5.4.10 under SSL VPN web portal allows an unauthenticated attacker to modify the password of an SSL VPN web portal user via specially crafted HTTP requests.  
    
![alt text](https://raw.githubusercontent.com/milo2012/CVE-2018-13382/master/magic_backdoor.png "Magic Backdoor")
   
```
$ python CVE-2018-13382.py  -h
Usage: CVE-2018-13382.py [options]

Options:
  -h, --help   show this help message and exit
  -i IP        e.g. 127.0.0.1:10443
  -u USERNAME  
  -p PASSWORD  

```
