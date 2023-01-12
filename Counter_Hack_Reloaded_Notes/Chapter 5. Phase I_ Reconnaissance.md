# Notes
When launching an attack, the most effective attackers do their homework to discover as much about their target as possible. 
- Before firing up scanning tools, some teams take a day to multiple days performing recon
- recon isn't always tech oriented

# Low-Technology Reconnaissance: Social Engineering, Caller ID Spoofing, Physical Break-In, And Dumpster Diving

## Social Engineering
Social engineering exploits the weaknesses of the human element of our information systems, skilled attackers can achieve their goals without even touching a keyboard. 

When conducting a social engineering assault, the attacker first develops a pre-text for the phone call, a detailed scenario to dupe the victim. 

Good book on Social Engineering *The Art of Deception* By Kevin Mitnick

### In-House Voice Mailboxes and Spoofing Caller ID to Foster Social Engineering
A good way to establish almost instant credibility in some organizations is to have a phone number within the organization. 

The steps to establish this are:
1. After thoroughly researching the target organization, we pose as a new employee and call individuals there to ask them for the phone number of the computer desk
2. We then call the help desk and ask them for the number of the voice mail administrator.
3. Finally, we call the voice mail administrator, often posing as a new employee or an administrator, and request voice mail service. 
4. From there we can contact other employees, leaving them voice mails asking for sensitive information or password resets. 

The simplest way to spoof caller ID involves using a caller ID spoofing service. Several Internet-based exchanges allow their customers to place phone calls to a given number, sending a caller ID number of the attacker's choosing. 
- Star38 and Telespoof are two such organizations that sell their services to law enforcement agencies and investigators
- Camophone is targeted to the general public 

Many users have discovered that they can use Voice over IP (VoIP) services to make calls and alter their caller ID information. 
- By reconfiguring their VoIP equipment--especially using highly configurable, free VoIP Private Branch exchanges (PBXs) like Marc Spencer's Asterisk for Linux, OpenBSD, and Mac OS X-users can send any caller ID numbers they choose. 
- The specific procedure for altering the caller ID number depends on both the VoIP equipment and the VoIP service provider. 
![113d74d9baf3fdae70ad026bd24a5e1e.png](../_resources/113d74d9baf3fdae70ad026bd24a5e1e.png)

### Defenses Against Social Engineering and Caller ID Spoofing Attacks
User awareness is the best way to defend against social engineering and caller ID spoofing attacks is user awareness. 

Never give sensitive data over the phone no matter how friendly or urgent the request. 

Caller ID information cannot be trusted as a sole method for verifying someone's identity. 

## Physical Break-In 
Some attackers if possible, will break into the area they are attempting to attack. Just by plugging into the ethernet in the wall, attackers can begin scanning the network. 

Some attackers can even join companies just to steal their data. 

### Defenses Against Physical Break-Ins
Security badges issued to each and every employee are an obvious and widely used defense against physical break-in. 
- Make proper badge checks a deeply ingrained part of your organization. 

Access control vestibules work well for more sensitive areas

Track computer systems

Add locks to computer room doors and wiring closets. 

Consider installing a filesystem encryption tool on laptop machines with sensitive data

## Dumpster Diving 
Dumpster diving is a variation on physical break-in that involves rifling through an organization's trash, looking for sensitive information. 

### Defenses Against Dumpster Diving
Paper and Media shredders are the best defense against dumpster diving.


# Search The Fine Web (STFW)
In the computer industry if you ask someone a question with an obvious answer, you might be told to "RTFM" (Read the Fucking Manual)

Searching the Fine Web (STFW) is a great strategy for an attacker

## The Fine Art of Using Search Engines and Recon's Big Gun: Google
To maximize the usefulness of search engines in computer attacks, attackers must carefully formulate their queries. There are four important elements of Google's technology:
1. The Google Bots: These programs, which run on Google's own servers constantly surf the Internet, acting as Google's sentinels. They crawl Web site after Web site, following hyperlinks to retrieve information about what's out there. 
2. The Google Index: Based on what Google bots retrieve, Google creates a massive index of web sites. When you submit a query to Google, this index is what it searches through. Using an algorithm called PageRank, google associates similar web pages together 
3. The Google Cache: As the Google bots scour the Internet, they bring back a copy of the text of each document in the index, pulling in up to 101k of text for each page, including HTML, DOC, PDF, PPT, and a variety of other file types. These documents are stored in the Google cache, an immense amount of information represents Google's very own copy of a large portion of the Internet. 
4. The Google API: In addition to the normal Web-page interface for Google that was designed for us humans. Google has also created a method for computer programs to perform searches and retrieve results, known as the Google API. A program can create an Extensible Markup Language (XML) request and send it to Google using a protocol called Simple Object Access Protocol (SOAP). To use the Google API for your own programs or with programs written by others, you need a Google API key. 

Attackers try to maximize the precision of their search, using a variety of search directives and other search operators to retrieve items of max value. 

When searching Google with or without these directives, keep in mind these additional important tips:
- Remember to avoid putting a space between the directive and at least one of your search terms. The items should be smashed together (i.e., ```site:www.counterhack.net``` is good, but ```site wwwcounterhack.net``` with a space in it is usually bad). 
- Google searches are always case insensitive
- Google allows up to a maximum of 10 search terms, including each directive your provide. In other words ```site:counterhack.net skoudis``` contains two search terms, not one or three.

**[INSERT PICTURE HERE ON PAGE 199]**

Things get really interesting when attackers combine various search directives and operators to find useful information about given targets. For example, suppose an attacker wants to go after a large financial institution called the Freakishly Big Bank with a Web site located at ```www.thefreakishlybigbank.com``` The attacker could perform a search like this:
```site:thefreakishlybigbank.com filetype:xls ssn```

This search causes Google to look for all Microsoft Excel spreadsheets on the bank's site that contain "ssn", a common abbreviation for Social Security Numbers

Now instead of looking inside of spreadsheets or presentations, suppose the attacker wants to scour an entire site for references to SSN information. This type of search can be best done as follows:
```site:thefreakishlybigbank.com ssn -filetype:pdf```

The ```-filetype:pdf``` on the end filters out all PDF documents. Most PDFs are just forms for customers to fill out so not a whole lot of information there. 

Another useful alternative involves looking for active scripts and programs on the target site, including Active Server Pages (ASPs), Common Gateway Interface (CGI) scripts, PHP Hypertext Preprocessor (PHP) scripts, JavaServer Pages (JSPs) and so on. Given that there could be 1,000 or more of these types of pages in a given domain, I typically search for each one individually, looking for:
```
site:thefreakishlybigbank.com filetype:asp
site:thefreakishlybigbank.com filetype:cgi
site:thefreakishlybigbank.com filetype:php
site:thefreakishlybigbank.com filetype:jsp
```

With these results, I've harvested the target domain for various forms of user-activated scripts and programs that run on the Web site itself, each of which might have a security flaw. 

Johnny Long maintains a list of more than 1,000 useful searches to find vulnerable servers in his Google Hacking Database (GHDB) located at ```http://johnny.ihackstuff.com``` <-- You will need a wayback machine to reach this site

There are tools that automate Google recon for vulnerabilities. These tools are essentially nifty graphical front ends that query Google using its API and your Google API key to look for evidence of vulnerabilities in a site of your choosing. 
- Two of the most popular tools in this category are Foundstone's SiteDigger ```www.foundstone.com/resources/proddesc/sitedigger.htm``` and Wikto by Roelof (```www.sensepost.com/research/wikito)``` 
![771524742cf08b5dda0d3612284804bd.png](../_resources/771524742cf08b5dda0d3612284804bd.png)

Google can be used for looking at flights as well
![9cfdb4e9f8e2f5c9c5982ad3cf927b9e.png](../_resources/9cfdb4e9f8e2f5c9c5982ad3cf927b9e.png)

## Listening in At The Virtual Water Cooler: Newsgroups 
Another realm with great promise for an an attacker involves Internet newsgroups so frequently used by employees to share information and ask questions. News-groups often represent sensitive information leakage on a grand scale. Employees submit detailed questions to technical newsgroups about how to configure a particular type of system, get around certain software coding difficulties, or troubleshoot a problem. Attacks love this kind of request because it often reveals sensitive information about the particular vendor products a target organization uses and even the configuration of these systems.

## Searching An Organization's Own Web Site
In addition to search engineer recon and newgroup analysis, smart attackers also look extra carefully at a target's own Web site. Web sites often include very detailed information about the organization, including the following:
- Employees' contact information with phone numbers. These numbers can be useful for social engineering, and can even be used to search for modems in a war dialing exercise
- Clues about the corporate culture and language: Most organizations' web sites include significant information about product offerings, work locations, corporate officers, and star employees. An attacker can digest this information to be able to speak the proper lingo when conducting a social engineering attack. 
- Business partners: Companies often put information about business relationships on their web sites. Knowledge of these business relationships can be useful in social engineering. Additionally, by attacking a weaker business partner of the target organization, an attacker might find another way into the target
- Recent mergers and acquisitions: Many organizations forget about security issues or put them on the backburner during a merger. 
- Technologies in use: Some sites even include a description of the computing platforms and architectures they use. For example, many companies specifically spell out that they have built their infrastructure using Microsoft IIS Web servers and Oracle databases. 
- Open Job Requisitions: This type of data is really useful for attackers. If your websites says you are looking for NetScreen firewall administrators, it says two things: First, you are likely running NetScreen firewall. Second, and perhaps even more important, you don't have enough experienced staff to run your existing firewalls.

## Defenses Against Search Engine and Web-Based Reconnaissance
Start at home, by establishing policies regarding what type of information is allowed on your own Web servers. 

You can tell google not to index pages on your website. Google respects the following markers for data:
- The robots.txt file is a world-readable file in a Web server's root directory that tells well-behaved Web crawlers not to search certain directories, files, or the entire Web site. 
- The ```noindex``` meta tag tells well-behaved crawlers not to include the given Web page in an index
- The ```nofollow``` meta tag tells well-behaved crawlers not to follow links on a page in an effort to find new pages
- The ```noarchive``` meta tags says that a given page should be indexed (so it can be searched for) but should not be cached
- The ```nosnippet``` meta tag specifies that Google shouldn't grab summary snippets of your Web page for display with search results on Google

An example of some of these tags that you could place at the top of a Web page to keep it out of Google's index and archive would be as follows:
```<meta name="robots" content="noindex,noarchive"```

# Whois Databases: Treasure Chests of Information
Other useful sources of information are the various whois databases on the Internet, which act like Internet white pages listings. 
- These databases contain a variety of data elements regarding the assignment of domain names, individual contacts, and even Internet Protocol (IP) addresses. 
- When your organization establishes an internet presence for a World Wide Web server, e-mail servers, or any other services, you setup one or more domain names for your organization wit ha registration company known as a registrar. 

## Researching .com, .net .org, and .edu Domain Names
Registrars for domain names ending with .com, .net, .org, and .edu are commercial entities, competing for customers to register their domain names. The Internet Corporation For Assigned Names and Numbers (ICANN) has established an accreditation process for new and competing registrars. 
- Some registrars charge a handsome price and offer a variety of value-added services, whereas others are bare bones, offering free registration in exchange for ad space on your Web Site.

**List of Accredited Registrars on the InterNIC site**
![3ac15bc95914081af04bbc1cb7ad2ac1.png](../_resources/3ac15bc95914081af04bbc1cb7ad2ac1.png)


![5f972d05156edf240929a9a43b60da44.png](../_resources/5f972d05156edf240929a9a43b60da44.png)

## Researching Domain Names Other Than .Com, .Net, .ORG, .EDU, .AERO, .ARPA,.BIZ, .COOP, .INFO, .INT, and .MUSEUM
For organizations outside of the US, one of the most useful research tools is the Uwhois Web site. This site includes a front end for registrars in 246 countries, ranging from Ascension Island (.ac) to Zimbabwe (.zw). Uwhois points you to the appropriate registrar for any particular country you need to research. 

Additionally, for US military organizations, a quick trip to the whois database at ```www.nic.mil/dodnic``` reveals registration information. 


### We've Got Registrar, Now What?
At this stage of reconnaissance, the attacker knows the target's registrar, based on data retrieved from InterNIC, Uwhois, or one of the other whois databases. Next, the attacker contacts the target's particular registrar to obtain the detailed whois entries for the target. 

Using the whois database, you can conduct searches based on a variety of different information including the following:
- Domain name, such as coutnerhack.net
- NIC handle (or contact), by typing a convenient alphanumeric value assigned to each record in the whois database, such as ESI1234
- IP address, by typing the dotted-quad IP address notation, such as 10.1.1.48

**Looking up a domain name at a particular registrar**
![bf13642dfbc721be5b1058c0df57c93e.png](../_resources/bf13642dfbc721be5b1058c0df57c93e.png)

# Summary