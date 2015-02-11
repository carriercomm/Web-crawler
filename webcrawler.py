#! /usr/bin/python

import socket                                      # socket related api's 
import sys                                         
import re                                          # for reg-exes
from HTMLParser import HTMLParser                  # for HTML parsing
from bs4 import BeautifulSoup			   # for HTML parsing

## constants declaration  
username = sys.argv[1]                                                         # user-name of student
password = sys.argv[2]							       # password of student
server_port = 80                                                               # port used by HTTP : 80
host_addr = "cs5700f14.ccs.neu.edu"                                            # host address
loginFormURL = "http://cs5700f14.ccs.neu.edu/accounts/login/?next=/fakebook/"  # LOG-IN page for fakebook
loginURL = "http://cs5700f14.ccs.neu.edu/accounts/login/"                      # login url used for HTTP POST
fbHomePage="http://cs5700f14.ccs.neu.edu"                             
htmlstarttag = "<html>"                                                        # html start tag                                         
htmlendtag = "</html>"                                                         # html end tag
## constants declaration ends here

## Various codes that are handled by this web-crawler
CODE_OK = "HTTP/1.1 200 OK"						       # OK code
CODE_MOVED_PERMANENTLY = "HTTP/1.1 301 Moved Permanently"		       # code for redirecting to new url
CODE_FORBIDDEN = "HTTP/1.1 403 Forbidden"                                      # code for page forbidden
CODE_NOT_FOUND = "HTTP/1.1 404 Not Found"                                      # code for page not found 
CODE_FOUND = "HTTP/1.1 302 FOUND"                                              # code for page found
CODE_INTERNAL_SERV_ERROR ="HTTP/1.1 500 Internal Server Error"                 # code for internal server error
## constants declaration for http codes ends here

csrfToken = ""                                                                 # initialzing csrf token to empty string
sessionToken = ""                                                              # initialzing csrf token to empty string
sock = socket.socket(socket.AF_INET , socket.SOCK_STREAM)                      # creating a AF-INET, TCP socket
url_list=[]
secret_flag_count=1

##+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

## template for MyHTMLParser with overridden handle_starttag method
class MyHTMLParser(HTMLParser):
    
	token = "" 
    	def handle_starttag(self,tag,attrs):
        	flag = 0
        	for attr in attrs:
        		searchObj = re.search("csrfmiddlewaretoken",str(attr))      # extracting csrfmiddleware token from 
										      #   login form page
			if ( flag == 1):
                        	MyHTMLParser.token = attr
                        	flag = 0
            		if searchObj:                                                 # "csrfmiddlewaretoken" found, next attr will 
                		flag = 1                                              #   contain actual value
			if  str(attr[0])=="href" and str(attr[1]).find("/fakebook") is not -1:
            			if url_list.count(str(attr[1])) < 1:
                        		search_secret_flag((str(attr[1])))
                        		url_list.append(str(attr[1]))

##+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
## Function declarations starts here

def connectToServerPort():
	
	sock.connect_ex((host_addr,server_port))	                               # connecting to the http port

##+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

def issueGET(url):

	requestData = constructGETRequest(url)                                         # construct GET using given url
	sock.send(requestData)                                                         # send GET request via socket
	response = readResponse(sock)                                                  # read the socket
	if(re.compile(htmlstarttag,re.MULTILINE).findall(response)) :                  # detects partial http response  
 		if (not re.compile(htmlendtag,re.MULTILINE).findall(response)):        #    from server. html start and
			response1 = readResponse(sock)                                 #    end tag have to be present 
			return response + response1	                               #    for a response to be complete
			 							       #    reads socket again to obtain 
	return response								       #    full response

##+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	
def issuePOST():
	
	requestData = constructPOSTRequest() 					       # constructing HTTP POST request
	sock.send(requestData)                                                         # sending HTTP POST header over sock
	response = readResponse(sock)                                                  
	return response

##+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

def readResponse(sock):
	
	return sock.recv(8192)							       # socket read operation with buffet 
										       # 8192 bytes

##+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

def constructGETRequest(url):
	
	if (url==loginFormURL):                                                    # HTTP GET Header for login form of 
										       # fakebook
		reqHeader = "GET " + str(url) + " HTTP/1.1\n" + "Host: cs5700f14.ccs.neu.edu\n\n"
	else:
	# GET HTTP header with sessionid and csrf token appended for the rest of the links 
		reqHeader = "GET " + url + """ HTTP/1.1\nHost: cs5700f14.ccs.neu.edu\nConnection: keep-alive\nCache-Control: max-age=0\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\nUser-Agent: Mozilla/5.0\nReferer: http://cs5700f14.ccs.neu.edu/accounts/login/?next=/fakebook/\nAccept-Language: en-US,en;q=0.8\nCookie: csrftoken=""" + csrfToken +"; sessionid=" +sessionToken +"\n\n"		
	return reqHeader

##+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

def constructPOSTRequest():
      
        # HTTP POST request header with url encoded content. content contains csrf token, username and password
	reqHeader = "POST " + loginURL + """ HTTP/1.1
Host: cs5700f14.ccs.neu.edu                                                            
Connection: keep-alive
Content-Length: 109
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Origin: http://cs5700f14.ccs.neu.edu
User-Agent: Mozilla/5.0
Content-Type: application/x-www-form-urlencoded
Referer: http://cs5700f14.ccs.neu.edu/accounts/login/?next=/fakebook/
Cookie: csrftoken=""" +csrfToken + "; sessionid=" + sessionToken + "\n\nusername=" +\
 username + "&password=" + password + "&csrfmiddlewaretoken=" + csrfToken + \
"&next=%2Ffakebook%2F\n\n"
	return reqHeader

##+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

def handleErrorCode (serverResp, url):
	
	# this checks for Page OK and Page Found code in http response
	if (re.match(CODE_OK,str(serverResp),re.I) or  re.match(CODE_FOUND,str(serverResp),re.I)): 
		return serverResp
	# checks for forbidden code in the response. returns forbidden code declared in the constant declaration
	# area 
	elif (re.match(CODE_FORBIDDEN,str(serverResp),re.I) or re.match(CODE_NOT_FOUND,str(serverResp),re.I)):
		return CODE_FORBIDDEN
	# checks for code 500, retries again  	
	elif (re.match(CODE_INTERNAL_SERV_ERROR,str(serverResp),re.I)):
		return getPage( url )
	# checks for moved permanently code, tries to fetch new location and content from new url
	elif (re.match(CODE_MOVED_PERMANENTLY,str(serverResp),re.I)):
		temp = re.search('Location: (.+?)\n',str(serverResp))
        	if temp:
			newurl = temp.group(1)
			return getPage(newurl)
	else :
		global sock 
		sock = socket.socket(socket.AF_INET , socket.SOCK_STREAM)            # unknown code is dealt by creating new
		connectToServerPort() 						     # socket and reconnect to port 80. 
									             # this usually happens
										     # when server closes the connection
		return getPage(url) 

##+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
		
def logIntoFB():
	
	global csrfToken, sessionToken
	csrfToken=""
	sessionToken=""
	sock = connectToServerPort( )							# connect to server port
	fbResp = getPage( loginFormURL )						# get the login form in html
	parser = parse_html(fbResp)
	csrfToken = parser.token[1]							# get csrfmiddlewaretoken
	temp = re.search('sessionid=(.+?);',str(fbResp))				# get temporray sessionid
	if temp:
		sessionToken = temp.group(1)	
        	fbResp1 = issuePOST( )							# using csrftoken and temporary 
	temp = re.search('sessionid=(.+?);',str(fbResp1))				# sessionid, issue POST request
	if temp:
		sessionToken = temp.group(1)						# get actual sessionid
	if( csrfToken == "" and sessionToken == ""):					# check for proper csrftoken
        	print "Login to Fakebook failed ! \n"					#   and sessionid
		logIntoFB()								# in case of failed login,
											#   retry login
##+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

def getPage(pageURL):
											# function to get any page using link
	fbResp = issueGET(pageURL)
	return handleErrorCode(fbResp, pageURL)                                         # handles error codes here and
											# and gives proper response
##+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 										
def parse_html(page):                                                                   #function to call html parser while crawling

        parser = MyHTMLParser()								
        parser.feed(page)
	return parser

##+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

def crawl():
        for link in url_list:								#for each link added to the global url list
                if(secret_flag_count!=6):						#parse the html 
                        parse_html(getPage(fbHomePage+link))
                #url_list.remove(link)

##+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

def print_list():									#print the links presen in the global url list
        for link in url_list:
                print link

##+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

def search_secret_flag(page):
        if page is not None:
                global secret_flag_count                                               #accessing the global secret flag count
                soup = BeautifulSoup(getPage(fbHomePage+page))			       #create a soup object for the page
                secret_flag_list=soup.find_all('h2',{"class":"secret_flag"},text=True) # searching for tags containing secret flags
                for secret_flag in secret_flag_list:				       # extract only the secret flags from the tags
                        if len(secret_flag) is not 0:
                                secret_flag_text=secret_flag.get_text()
                                secret_flag_count +=1
                                print secret_flag_text[6:70]

## Function definitions end here
##+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

## crawling starts here
logIntoFB()										# log in to fakebook. populate
											#    csrftoken and sessionid
if( not csrfToken and not sessionToken):						# if csrftoken and session id  
        print "Login to Fakebook failed ! \n"						#    are still empty, its a case
        sys.exit()									#    of failed login. exit      
parsed_list = parse_html(getPage(fbHomePage+"/fakebook/"))
crawl()                                                                                 

## crawling ends here
##++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
