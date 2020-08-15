# Bug Bounty Checklist

**Bug bounty reference document dumping checklist deteriorating... First gathering information** <br>
Personal reference, organizational documents. Checklist later.. <br>
Translation reference https://ok-chklist.readthedocs.io/ko/latest/index.html

---

## Information Gathering

### OTG-INFO-001 Search for information exposed to search engines

#### Checklist

#### Existing Tools
* Search engine

#### Automation ideas
* Rather than automatic search, it is better to collect queries so that you can search more conveniently and search by pressing a button

#### Bug Bounty Case 
This kind does not give bounty well. 

* [Securing "Reset password" pages from bots](https://hackerone.com/reports/43807)
	* Sensitive page appeared in search engine search results. 
* [Insecure Direct Object Reference on API without API key](https://hackerone.com/reports/284963)
	* You could call the API without an API key using the URL found in Google.
	* Googleing with queries such as `site:*.api.domain.com`
* [Research papers on yelp are getting indexed by google bots](https://hackerone.com/reports/207435) 
* [Slack token leaking in stackoverflow and devtimes](https://hackerone.com/reports/448849)
	* Pointed out that the webhook URL containing the Slack token was uploaded in Stack Overflow and Dev Time. 

---

### OTG-INFO-002 web server fingerprinting

#### Checklist
* Check Server header in general HTTP Response
* Check if server information is leaked from the error page
* Inferred via HTTP header field order
* Inferred through HTTP header field type that comes with 400 response

#### Existing Tools
* [httprint](https://net-square.com/httprint.html)
	* Open source X, personal free. Last update: 2005
* [httprecon](https://www.computec.ch/projekte/httprecon/)
	* Open source, HTTPS available, Fingerprint database available, Last update: 2009
* [software-version-reporter](https://github.com/portswigger/software-version-reporter)
	* Open source, Burpsuite plugin.

#### Automation ideas
* If version information is extracted by fingerprinting, CVE recommendations are also provided.

#### Bug Bounty Case
* [Out-of-date Version (Apache)](https://hackerone.com/reports/184877)
	* Point out that the vulnerable version of the web server is used. CVEs that can be attacked on the version of the web server are listed, and explanations are also added.
* [RCE and Complete Server Takeover of http://www.█████.starbucks.com.sg/](https://hackerone.com/reports/502758)
	* RCE to find a valid CVE with the web server version obtained by stack trace 

---

### OTG-INFO-003 Check the web server meta file to confirm information disclosure 

#### Checklist
* Check robots.txt file
* Check meta tag of web page that is prohibited from crawling in robots.txt
* Check meta tag of web page with sensitive data

#### Existing Tools

#### Bug Bounty Case
* [Securing sensitive pages from SearchBots](https://hackerone.com/reports/3986)
	* Point out that the meta tag noindex, nofollow tag is not hung.
	* In particular, be careful when sending a token in the GET parameter.

---

### OTG-INFO-004 Web server application check

#### Checklist
* IP-> Find domain, or reverse

#### Existing Tools
* [Sublist3r](https://github.com/aboul3la/Sublist3r)
	* Subdomain enumeration
* [VHostScan](https://github.com/codingo/VHostScan)
* [Amass](https://github.com/OWASP/Amass) 
	* [Reference article](https://0xpatrik.com/subdomain-enumeration-2019/) 
	* OWASP's subdomain tool
* [dnspop](https://github.com/bitquark/dnspop)

#### Automation ideas
* Find Subdomain takeover vulnerability
	* Use search engine/DNS queries to find subdomains and find out if takeover is possible. 
	* DNS query using subdomain + bruteforce from search 
	* Query using frequently used domain phrases

#### Bug Bounty Case
* [Sub Domain Take over](https://hackerone.com/reports/111078)
	* Report a bug with Broken Link Hijacking
* [Bulgaria-Subdomain takeover of mail.starbucks.bg](https://hackerone.com/reports/736863)
	* Scan `*.starbucks.*` to see that mail.starbucks.bg is pointing to an ownerless service
* [Subdomain takeover at news-static.semrush.com](https://hackerone.com/reports/294201)
	* The subdomain CNAME points to Amazon S3, but it is not registered with Amazon. I could take over this subdomain. After purchasing the domain directly, it was presented as a PoC.
* [Subdomain takeover on slack.augur.net pointing to GitHub Pages](https://hackerone.com/reports/382995)
	* The subdomain was pointing to a nonexistent Github page. I created a Github page, registered the subdomain as a custom domain, and took over the subdomain.


---
### OTG-INFO-005 Check comments or metadata

#### Checklist

#### Existing Tools

#### Automation ideas
* Pull out comments and recommend data that seem important

#### Bug Bounty Case

---

### OTG-INFO-006 Application entry point identification

#### Checklist
* GET parameters, cookie settings, HTTP error page, unique HTTP method usage point, custom HTTP header, etc.

---

### OTG-INFO-007 route mapping

#### Existing Tools
* Burpsuite 
* Crawler

#### Bug Bounty Case
* [Real Time Error Logs Through Debug Information](https://hackerone.com/reports/503283)
	* Go to slackb.com/debug and see that you can see debugging information

---

### OTG-INFO-008 Web Application Framework Fingerprinting

#### Checklist
* Framework identification, version identification with HTTP header, path, cookie, and HTML code specific to the framework

#### Existing Tools
* [Whatweb](https://www.morningstarsecurity.com/research/whatweb)
	* Open source, still updated, Kali basic tools
* [BlindElephant](http://blindelephant.sourceforge.net/)
	* Open source, out of date
* **[Wappalyzer](https://www.wappalyzer.com/)**
	* Open source, updated now
	* Simple, fingerprint search is possible by searching domains on the web
	* Available as a browser extension

---

### OTG-INFO-009 Web application fingerprinting

#### Checklist
* Application specific cookie, HTML code, file or directory name
* Dirbusting to explore possible files/directories

#### Existing Tools
* [Whatweb](https://www.morningstarsecurity.com/research/whatweb)
	* Open source, still updated, Kali basic tools
* [BlindElephant](http://blindelephant.sourceforge.net/)
	* Open source, out of date
* **[Wappalyzer](https://www.wappalyzer.com/)**
	* Open source, updated now
	* Simple, fingerprint search is possible by searching domains on the web
	* Available as a browser extension

---

### OTG-INFO-010 Application Architecture Mapping
#### Checklist
* Architecture investigation such as firewall, reverse proxy, load balancer, DB, etc.
	* Can be judged by viewing HTTP headers or TCP responses

---

### OTG-CONFIG-001 Network/Infrastructure Setting Test

* Testing for known vulnerabilities, management tools, authentication systems, etc.

#### Bug Bounty Case
* [Out-of-date Version (Apache)](https://hackerone.com/reports/184877)
	* Point out that the vulnerable version of the web server is used. CVEs that can be attacked on the version of the web server are listed, and explanations are also added.

---

### OTG-CONFIG-002 Application platform configuration test

* Check the sample program or default setting that comes with the platform installation. Permission setting, firewall setting, logging setting, etc.

#### Bug Bounty Case
* [Real Time Error Logs Through Debug Information](https://hackerone.com/reports/503283)
	* Go to slackb.com/debug and see that you can see debugging information

---

### OTG-CONFIG-003 File extension handling test

* You can guess the technology stack used by the server through the file extension. 
* Test to see if you can open an extension containing sensitive information. 

---

### OTG-CONFIG-004 Backup and test unreferenced files
* Find out if you can access the renamed files, backups (snapshots) created automatically by the program, and forgotten files. 
* Since the backup changes to a different extension than the original file's extension (ex: .old), it can be transferred as a normal string. Possible server code leak.

---

### OTG-CONFIG-005 Infrastructure and application manager interface verification
* Check if you can access the admin page. 
* Test default location, brute force, administration port, etc.
* Basic ID/PW test

---

### OTG-CONFIG-006 HTTP method test
* Check if various HTTP methods are available
* Use of TRACE, OPTIONS, etc.
* Check if there is a method created randomly 

#### Bug Bounty Case
* [Weblate |Security Misconfiguration| Method Enumeration Possible on domain](https://hackerone.com/reports/230648)
	* Point out that the HTTP OPTIONS method is possible. There is no bounty.

---

### OTG-CONFIG-007 HSTS check
* HTTP Strict Transport Security (HSTS) header check
	* This means that this domain only supports HTTPS

#### Bug Bounty Case
* [SSO through odnoklassniki uses http rather than https](https://hackerone.com/reports/703759)
	* When you click Login with odnoklassniki on the login page, the URL to be redirected to HTTP is sent. Using this, it was possible to log in to the attacker's account on the victim's PC.
	* It is not possible to report simply that there is no HSTS, but in this case, even with HSTS, there was a possibility of an attack. 

---

### OTG-CONFIG-008 RIA Cross Domain Policy Test
* Create a policy file to allow connection with other domains. If it is configured incorrectly, it can allow unintended domain connections.
	* Whenever the web client detects that a resource must be requested from another domain, it first looks for a policy file in the target domain and checks whether the connection is allowed. 
	* There are several detailed settings such as socket permission, header permission, HTTP/HTTPS access permission, etc.
* Overly allowed cross-domain policy abuse / Generate server response that can be treated as a policy file / Upload a manipulated policy file using the file upload function
	* This can disable CSRF protection. 

#### Automation ideas
* Crawl the crossdomain.xml file to see if it exists, and check if there are any vulnerable rules. 

#### Bug Bounty Case
* [Possible SOP bypass in www.starbucks.com due to insecure crossdomain.xml](https://hackerone.com/reports/244504)
	* Point out that there are too lenient rules such as `*.example.com` in the crossdomain.xml file, and among them, there are domains that can be subdomain takeover.
* [OAuth 2 Authorization Bypass via CSRF and Cross Site Flashing](https://hackerone.com/reports/136582)
	* CSRF is performed by bypassing CSRF defense using generous crossdomain.xml rules 
* [Same Origin Policy Bypass at ██████.com](https://hackerone.com/reports/399427)
	* Found generous rules in crossdomain.xml. As a result of scanning the subdomain, we found a domain that uses a vulnerable version of the web server. You can bypass the SOP by opening a reverse shell with CVE and uploading a file.
* [Crossdomain.xml too permissive on eu1.badoo.com, us1.badoo.com, etc](https://hackerone.com/reports/96662)
	* crossdomain.xml was set too generously.
* [Risk of having secure=false in a crossdomain.xml](https://hackerone.com/reports/105463)
	* Pointed out that setting secure="false" in the allow-access-from node in crossdomain.xml is not secure. Means to allow HTTP requests as well.

---
## identity management test

### OTG-IDENT-001 role definition test
* Divide roles and privileges. What roles have what rights, and what restrictions are there in a table.

---
### OTG-IDENT-002 User registration process test
* Whether it is possible to forge/fake identity information when signing up
* Whether the same person can register multiple times
* Whether users can sign up with different privileges

#### Bug Bounty Case
* [Bypass Email Verification using Salesforce - Reproducible in gitlab.com](https://hackerone.com/reports/617896)
	* Point out that there is a way to sign up for membership without e-mail verification

---

### OTG-IDENT-003 Account supply process test
#### Bug Bounty Case
* [Bypass Email Verification - Able to Access Internal Gitlab Services that use Login with Gitlab and Perform Check on email domain](https://hackerone.com/reports/565883)
	* Point out that you can sign up without email authentication by registering an account with @gitlab.com using SCIM.

---

### OTG-IDENT-004 Account listing, gambling test
* Test if you can collect valid usernames
* Guess which ID was created through the login/signup error message. Use the error message that appears on the screen, the error code, or the difference in the URL in case of success/failure.
	* There may be differences in `www.foo.com/account1`, such as returning 403 if there is an accout1 account, and 404 if not.
	* There may be an error name in the web page title. 
	*200, but it can also show error messages as images or text. 
* In the case of an automatically created account, you can follow the schedule rules. Can try publishing
* You can publish using the ID found through Google Ring.

#### Bug Bounty Case
* [Email enumeration at SignUp page](https://hackerone.com/reports/666722)
	* When I try to sign up with an email that I have already signed up for, an error message pops up. He pointed out that this allows you to list the emails you have subscribed to.
* [Email Enumeration (POC)](https://hackerone.com/reports/47627)
	* The HTTP response code was different when an already registered email or incorrect email was entered in the email change function. Through this, I was able to list the emails I subscribed to by brute force.

---
### OTG-IDENT-005 Username Policy Test
* Test weak or unenforced username policy. 
* Check if it is easy to list the accounts, and if you can guess from the response of the server. 
* Almost similar to OTG-IDENT-004.

---
## Certification test

### OTG-AUTHN-001 Authentication information transmission test in encrypted channel
* Check whether to send login information via HTTP. 
* When switching to HTTP -> HTTPS when logging in, check if SSL strip attack is possible. 
	* HSTS header check
* Even in HTTPS, do not send passwords, etc. to the GET method URL parameter. Check this.
### Bug Bounty Case
* [Login form on non-HTTPS page](https://hackerone.com/reports/214571)
	* Pointed out that ID/PW is transmitted by HTTP.
* [Login form on non-HTTPS page on http://stream.highwebmedia.com/auth/login/](https://hackerone.com/reports/386735)
	* Pointed out that ID/PW is sent over HTTP. 

---
### OTG-AUTHN-002 Default Account Test
### Bug Bounty Case
* [Thailand – a small number of alarm system portals accessible with the default credentials](https://hackerone.com/reports/406486)
	* Pointed out that the default account of the AAP IP Module alarm system can be used.
* [SAP Server-default credentials enabled](https://hackerone.com/reports/195163)
	* Pointed out that the default account of the SAP server can be used. 

---

## input validation test

### OTG-INPVAL-001 Reflected XSS

#### Checklist
* Find Input Vector
	* GET parameters
	* HTTP header
	* POST data
		* Form value
		* Hidden Form value
		* Pre-defined/or selected button values
	* **Input Vector Listing Using Tool**
* Check whether to bypass filtering
	* HTML special characters such as ```>, <, &, /, `,', "```
	* String like ```script, javascript, img```
	* ```\n, \r, \uXXXX ``` 
	* **Payload test using fuzzer**
#### Automation ideas
* Determine whether to filter major special characters/keywords, and recommend them in the order of XSS probability 
	* To help before manually testing XSS

#### Bug Bounty Case
* [XSS vulnerable parameter in a location hash](https://hackerone.com/reports/146336)
	* XSS was possible in a script that prints the value received as a GET parameter as a log.
* [DOM XSS at https://www.thx.com in IE/Edge browser](https://hackerone.com/reports/702981)
	* The current page URL is imported and used as window.location.href. IE or Edge browsers do not encode window.location.href, so when entering a URL such as `https://www.thx.com/#'><img src=x onerror=alert(document.domain)>` XSS was possible.
* [Reflected Cross site Scripting (XSS) on www.starbucks.com ](https://hackerone.com/reports/438240)
	* I put the Return URL in the HTTP parameter as a JavaScript schema.
* [Reflected XSS in pubg.com](https://hackerone.com/reports/751870)
	* The "Show more" button was created using the value received as the GET parameter. The parameters are like a search query. XSS was possible by using this parameter without filtering.

---

### OTG-INPVAL-002 Stored XSS

#### Checklist

#### Bug Bounty Case
* [Stored XSS in vanilla](https://hackerone.com/reports/496405)
* [Cross-site Scripting (XSS)-Stored in RDoc wiki pages](https://hackerone.com/reports/662287)
	* Clickjacking and phishing attacks are possible due to lack of filtering. Also, XSS was possible.
* [Stored XSS in Snapmatic + REditor comments](https://hackerone.com/reports/309531)
	* XSS was possible using several bypass methods. 
* [Stored XSS in comments](https://hackerone.com/reports/148751)
	* In the comment, the URL of the author's website was entered as the href attribute of the anchor tag. XSS was possible by using the website URL as a javascript schema.

---
### OTG-INPVAL-005 SQL injection

#### Checklist

#### Existing Tools
* Burpsuite Intruder

#### Bug Bounty Case
* [SQL Injection on sctrack.email.uber.com.cn](https://hackerone.com/reports/150156)
	* SQLi was possible in the data transmitted by encoding the json data in base64.
* [SQL Injection Extracts Starbucks Enterprise Accounting, Financial, Payroll Database](https://hackerone.com/reports/531051)
	* When the XML file is uploaded, its contents are put into the DB. SQLi could do this.

---

### OTG-INPVAL-016 HTTP Splitting/Smuggling

#### Checklist

#### Bug Bounty Case
* [HTTP Request Smuggling on vpn.lob.com](https://hackerone.com/reports/694604)
* [Multiple HTTP Smuggling reports](https://hackerone.com/reports/648434)
	* Presenting HTTP sumggling CVE of several programs

---

### OTG-INPVAL-013 OS command injection

#### Checklist

#### Bug Bounty Case
* [Local files could be overwritten in GitLab, leading to remote command execution](https://hackerone.com/reports/587854)

---

### OTG-INPVAL-014 buffer overflow

#### Checklist

#### Bug Bounty Case
* [Security check failure or stack buffer overrun (crash)](https://hackerone.com/reports/481335)

---

## error handling

### OTG-ERR-002 stack trace analysis

#### Checklist

#### Bug Bounty Case
* [RCE and Complete Server Takeover of http://www.█████.starbucks.com.sg/](https://hackerone.com/reports/502758)
	* RCE to find a valid CVE with the web server version obtained by stack trace 

---

## encryption test 

### OTG-CRYPST-003 Sensitive data unencrypted channel transmission 
#### Bug Bounty Case
* [Invitation reminder emails contain insecure links](https://hackerone.com/reports/327674)
	* Point out that there is an http link in the mail. (Not https)
* [SSO through odnoklassniki uses http rather than https](https://hackerone.com/reports/703759)
	* When you click Login with odnoklassniki on the login page, the URL to be redirected to HTTP is sent. Using this, it was possible to log in to the attacker's account on the victim's PC.
	* It is not possible to report simply that there is no HSTS, but in this case, even with HSTS, there was a possibility of an attack. 
* [Unsecure cookies, cookie flag secure not set](https://hackerone.com/reports/6877)
	* He pointed out that the secure flag should be set for the session cookie or important cookie, but it was not set. 
* [Login form on non-HTTPS page](https://hackerone.com/reports/214571)
	* Pointed out that ID/PW is transmitted by HTTP.

---

## Business logic test

### OTG-BUSLOGIC-008 Unexpected file format upload

#### Checklist
* Filtering bypass 
	* Space, insert special characters

#### Bug Bounty Case 
* [Webshell via File Upload on ecjobs.starbucks.com.cn](https://hackerone.com/reports/506646)
	* Bypass filtering by including a space at the end of the file name (after the extension)
* [XXE at ecjobs.starbucks.com.cn/retail/hxpublic_v6/hxdynamicpage6.aspx](https://hackerone.com/reports/500515)
	* Uploading XML files using file upload vulnerability, up to XXE

---

## client-side testing

### OTG-CLIENT-005 CSS Injection test

#### Bug Bounty Case 
* [CSS Injection to disable app & potential message exfil](https://hackerone.com/reports/679969)
	* CSS injection is possible for the function that changes the theme with the value input from the user