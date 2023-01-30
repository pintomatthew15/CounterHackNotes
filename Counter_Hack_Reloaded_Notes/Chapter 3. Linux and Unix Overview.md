# Notes
There is no single operating system called UNIX. Instead, UNIX is a family of operating systems, with members of the family constantly being updated by many competing vendors, individuals, and even standards bodies with different visions and goals. 

Linux is really the name for the kernel. Popular Linux distributions include: Debian, Gentoo, Mandrake, Red Hat, Slackware, and SuSE. 

To lookup a man page for a given command, simply type the following at a command prompt:
```$  man [system command]```

## Architecture
### Linux and UNIX File System Structure
Linux and Unix are very much organized around their file system structure.

The top of the file system is known as the "root" directory, simply because it's at the top and all other directories are under it. Below the root directory, a number of other directories hold the rest of the information on the machine, including system configuration, system executables, and user data.

![7a93f6356a1ea70903f499251159317d.png](../../_resources/7a93f6356a1ea70903f499251159317d.png)
![bcc52f641b583a8064330db5bfd5a360.png](../../_resources/bcc52f641b583a8064330db5bfd5a360.png)
![7aef1923416da84244376c801050e45e.png](../../_resources/7aef1923416da84244376c801050e45e.png)
![ac58cbc9da65446105d8aca53bf8c251.png](../../_resources/ac58cbc9da65446105d8aca53bf8c251.png)

The other directory names are of paramount importance in UNIX: the names "." and "..", These names don't refer to just one directory in the file system. They are are links inside every directory to refer to the current directory and the parent directory respectively. 
- We can refer to files in the current directory as ./filename when running commands.

# The Kernel and Processes
The kernel is the special program at the core of  the operating system. When a running program needs to access hardware components, such as disks or network interfaces, it calls on the kernel, which provides the required functions to access the hardware. 

When a program runs on a Linux or UNIX system, the kernel starts a process to execute the program's code. A process contains:
- The running program's executable code
- The memory associated with the program
- Various threads of execution that are moving their way through the code executing its instructions

Processes are like bubbles that contain all the guts of a running program. The kernel inflates the bubbles (by creating processes), controls the flow of bubbles, and tries to keep them from popping one another. 
- The kernel juggles the CPU among all of the active processes, scheduling each one so that the system's processor can be shared among the processes. 
 ![499e065a93567f0aec0e4703cbc0937b.png](../../_resources/499e065a93567f0aec0e4703cbc0937b.png)
 
 Many processes on Linux and UNIX systems run in the background performing critical system functions, such as spooling pages to be sent to a printer, providing network services such as file sharing or Web access. These background processes are known as daemons. 
 - Daemons are commonly given names based on the function they perform, followed by a "d" to indicate they are a daemon. For example the SSH daemon (sshd) allows users and administrators to access the system securely across the network using a command line. 

### Automatically Starting Up Processes: Init, Inetd, Xinetd, and Cron
All processes running on a Linux or Unix system, from the mightiest Web server to the lowliest character generator, have to be activated by the kernel or some other process to start running. 
- During system boot, the kernel first gets loaded into memory. Then the kernel itself activates a daemon called init, which is the parent of all other user-level processes running on the machine. Init's job is to finish the bootstrapping process by executing start-up scripts to finalize the configuration of the machine and to start up a variety of system processes. 

Init also starts a bunch of processes associated with network services. These network service daemons are activated, listen on a specific port for incoming traffic, and interact with the network traffic. Some of the most common network services daemons started by init include the following:
- Httpd: A Web server, handling HTTP or HTTPS requests
- Sshd: The SSH service, offering strongly encrypted and authenticated remote shell access
- Sendmail: A common UNIX implementation of an e-mail server
- NFS: The Network File System, originally created by Sun Microsystems, used to share files between UNIX systems.

To improve performance, some Linux and UNIX network services are not started by init and don't just sit and wait for traffic. Instead, another process called the Internet Daemon, or inetd for short, does the waiting for them.
- init configuration information can be found in the ```/etc``` directory
- When traffic arrives at the machine destined for a specific service identified in its configuration file or directory, inetd or xinetd activates the process associated with the service. 

Numerous services are commonly activated using inetd or xinetd, including the following:
- Echo: A service that just echoes back the characters sent to it, sometimes used to troubleshoot network connectivity problems
- Chargen: A service that generates a repeating list of letters, sometimes used to measure performance
- Ftpd: The FTP daemon, used to move files between machines
- Telnetd: A telnet server for remote command-line access offered on a clear-text (and thus quite unsecure) basis.
- Shell, login: These are the UNIX r-commands for remote shell (rsh) and remote login (rlogin), respectively, which allow a user to execute commands and log in remotely to the system, again in a very unsecure manner. 
- TFTP: a bare-bones file transfer mechanism 


To summarize, there are two basic types of network services on a Linux or UNIX machine: services that are started by init and constantly wait themselves for traffic from the network, and services that use inetd or xinetd to listen for traffic and are activated only when traffic arrives for the service. The ```chkconfig``` command included in some Linux distributions can be used to display a list of all services configured to start up at system boot and by xinetd, by simply typing (as root): ```# chkconfig --list```

Beyond init, inted, and xinetd, another way to automatically start processes is through the ```cron``` daemon. This daemon is used to schedule the running of specific system commands and programs at predetermined times. 
- This is widely used by System Administrators
- Cron reads one or more configuration files called crontabs to determine what to run and when to run it. Common locations of crontab files are ```/usr/lib/crontab``` and ```/etc/crontab```
![a54a451737b7fea570fea1e00f26e827.png](../../_resources/a54a451737b7fea570fea1e00f26e827.png)

### Manually Starting Processes
Init, inetd (or xinetd), and cron automatically start processes running on a machine. Of course, users and administrators can manually start processes as well. 

When a user types a program name at a command prompt, the system looks for the program in a variety of directories that can be custom-tailored for that specific user. The directories searched for the program make up the search path for that user, or simply the path.
- The user's search path is really just a variable that contains all of the directories that are searched by default, with each directory in the path separated by a colon. 
- To see the setting of your search path, type the following command at a command prompt: ```$ echo $PATH```
- You will get a response similar to this: ```/usr/local/bin:/bin:/usr/bin:/usr/X11R6/bin```

This response indicates that when I type a particular program's name, the system will attempt to find the program first in the ```/usr/local/bin``` directory, then in the ```/bin``` directory and finally in the ```/usr/X11R6/bin``` directory. If it can't be found a message will be printed in the terminal saying such. 

It is very dangerous to have the current working directory in your search path. 
- If the . in your path comes before the directory where the real ```ls``` program is located, you will unwittingly execute a program named ls in your current directory. 

### Interacting with Processes
The kernel assigns each running process on a machine a unique process ID (called PID), which is a number used to refer to the process. You can use the ```ps``` command to generate a list of processes running on the machine.

![c128b991d923e2422f8b339ab78c1de5.png](../../_resources/c128b991d923e2422f8b339ab78c1de5.png)

Can also use ```lsof``` to print every file that every process on your system is accessing.
- You can run ```lsof``` by itself to get an enormous amount of information about every file that every process on your system is accessing or you can take the output and feed it through a pipe to the ```grep``` command to find specific patterns

One way to interact with processes is to send them a signal. Signals interrupt processes and tell them to do something.
- One of the most common signals is the TERM signal (short for terminate), which instructs the process and the kernel to stop the given process from running.
- Another frequently used signal is the hang-up signal (HUP), which causes many processes to reread their configuration files. 
- A user can run a ```kill``` command to send a signal to a specific process through PID or kill all processes with the ```killall``` command 

Suppose an attacker alters the configuration of xinetd by making a change to one of the files in the directory ```/etc/xinetd.d``` . To make the changes active on the system, xinetd must be forced to reread its configuration. To cause the xinetd process from the process list shown previously to reread configuration files, an administrator or attacker could use the kill command to refer to its PID:
```# kill -HUP 462```

Or alternatively, on Linux, the administrator could use the ```killall``` command to refer to the process name:
```# killall -HUP xinetd```

# Accounts and Groups
To log in to a Linux or UNIX machine, each user must have an account on the system. Furthermore, every active process runs with the permissions of a given account. 

## The ```/etc/passwd``` File
Accounts are created and managed using the ```/etc/passwd``` file, which contains one line for each account on the machine. An example ```/etc/passwd``` file might contain the following information:
![6a27644079fa6d13a9141dae059ce5d2.png](../../_resources/6a27644079fa6d13a9141dae059ce5d2.png)

Each line in the ```/etc/passwd``` file contains a description of one account, with parameters separated by a colon. The parameters are as follows:
- **Login Name**: This field contains the name of the account. A user logs into the machine using this name at the login prompt
- **Encrypted /hashed password**: This field contains a copy of the user's password, cryptographically altered using a one-way function so that an attacker cannot read to determine the user's passwords. 
- **UID Number**: Each account is assigned an integer called the user ID number. All processes and the kernel actually rely on this number and not the login name to determine the permissions associated with the account. 
- **Default GID number**: For the purposes of assigning permissions to access files users can be aggregated together in groups. This field stores the default group number to which this account belongs.
- **GECOS information**: This field is filled with free-form information not directly referenced by the system. Populated with general info about user
- **Home directory**: This value indicates the directory the user is placed in after logging into a system, the starting directory.
- **Login shell**: This field is set to the shell program that will be executed after the user logs into the system. This field is often set to one of the command-line shells for the system, such as the bourne shell (sh), the bourne-again shell (bash), C shell (csh), or Korn shell (ksh). 

Sometimes passwords are moved to the shadow file instead of the ```passwd``` file. This can be found at ```/etc/shadow``` or ```/etc/secure```. Super-user privileges can access this file only. 

## The ```/etc/group``` File
When administering a system, handling the permissions of each individual user account can be a lot of work. To help simplify the process, Linux and UNIX include capabilities for grouping users and assigning different permissions to the resulting groups. All groups are defined in the ```/etc/group``` file, which has one line for each group defined on the machine. A common ```/etc/group``` file might look like this:
![d50aba05bc4a7858eab381479e32ed74.png](../../_resources/d50aba05bc4a7858eab381479e32ed74.png)

The format of the ```/etc/group``` file includes the following fields, each separated by colons:
- **Group name**: This field stores the name of the group
- **Encrypted or hashed group password**: This field is never used, and is frequently just set to an x or a*
- **GID number**: This value is used by the system when making decisions about which group should be able to access which files
- **Group members**: The login name of each user in the group is included in this comma-separated list. In the example listed earlier, the root and bin accounts are all in the daemon group, which has a GID of 2. 

## Root: It's a Bird...It's a Plane...No, its a SUPER-USER!
The single most important and powerful account on Linux and UNIX systems is the root account, usually named root. Root has the maximum privileges' on the machine; it can read, write, or alter any file or setting on the system. 
- It has a UID of 0
- As long as the UID is zero, it is the root account regardless of name, system checks UID if a process requires super-user

# Linux and UNIX Permissions
Linux and UNIX file permissions are broken down into 3 areas: permissions associated with the owner of the file, permissions assigned to the owner group, and permissions for everyone. 
- For each of these three areas, at least three kinds of access are allowed: read, write, and execute. With three areas (owner, group owner, and everyone), there are 9 different standard permission settings. 
- Use the ```ls -l``` command to see permissions assigned to the files in a given directory. 
![2d38c5c43d0e89fda0348b0ecdb3526b.png](../../_resources/2d38c5c43d0e89fda0348b0ecdb3526b.png)

The next nine characters after the file designator indicate the permissions for each directory:
![f6be9d3ad753f2b90fdeb0525d8a4621.png](../../_resources/f6be9d3ad753f2b90fdeb0525d8a4621.png)

Permissions for each file can be altered using the ```chmod``` command. Suppose we had a file named ```foo``` that we wanted to have full control (read, write, and execute) capabilities for its owner account, we want it to be readable by the owner group, and we want everyone to be able to read and execute it. The desired permission set would be ```rwxr--r-x```, or converted to binary ```111 100 101```. The resulting octal representation would be 745. We set these permissions using this command:
- ```# chmod 745 foo```

![aff80ce3f858a43a526b804a68e0d663.png](../../_resources/aff80ce3f858a43a526b804a68e0d663.png)

 ![acd999f2cefc7b1fac38e5f633c36fda.png](../../_resources/acd999f2cefc7b1fac38e5f633c36fda.png)
 
 ## SetUID Programs
 Sometimes users or processes have a legitimate reason for accessing a file for which they don't have assigned permissions. Consider what must happen for users to change their own password. The user has to edit his or her account entry in the ```/etc/passwd``` or ```/etc/shadow``` file. However, the ```/etc/passwd``` or ```/etc/shadow``` files can only be altered with super-user-level permissions. 
 
 With the SetUID (set user id) capability, a particular program can be configured always to execute with the permissions of its owner, and not the permissions of the user that launched the program. 
 - Remember when a user starts a process, the process runs with the user's permissions. SetUID alters this, allowing a user to run a process that has the permissions of the program's owner, and not the user executing the program.

SetUID capabilities give common users temporary and controlled access to increased permissions so they can accomplish specific tasks on the system. Programs that use SetUID are identified with a special bit in their permissions settings. This bit is actually located before the nine standard permissions (rwxrwxrwx). 
- In fact there are 3 additional bits that can be used in addition to the 9 standard permissions. These bits are the SetUID bit, the SetGID bit, and the so-called sticky bit, which forces programs to stay in memory and limits deletion of directories. 

Therefore to change the file from our earlier example, ```foo```, to run SetUID, the owner of the file (or root) could type:
```# chmod 4745 foo```

The leading "4" is the octal equivalent of the binary "100", meaning that the SetUID bit is set, whereas the SetGID bit and sticky bit are not. 

When the ```ls``` command is used to display permissions, it does indicate which files are SetUID by overwriting the x for the file's owner with an ```s``` character, as shown below:
![50fb87a559cc20558b5c5d373c59eebc.png](../../_resources/50fb87a559cc20558b5c5d373c59eebc.png)

Any program that is SetUID, particularly ones created by root, must be carefully constructed to make sure that a user cannot exploit the program. If attackers have an account on a system and can run SetUID programs, they can attempt to break out of the SetUID program to gain increased privileges. 

To find all SetUID programs on a UNIX machine, you can run the following command as a root-level user:
![558f8587898a8a60d1fe441e7edacbc8.png](../../_resources/558f8587898a8a60d1fe441e7edacbc8.png)


# Linux and Unix Trust Relationships
Linux or Unix machines can be configured to trust each other, an operation that can make the systems simpler to administer, but potentially impacting security. 

![3c3a5a51ab8a38b9fb071c0eafb25d06.png](../../_resources/3c3a5a51ab8a38b9fb071c0eafb25d06.png)

This trust can be implemented in Linux and UNIX systems using the system-wide ```/etc/hosts.equiv``` file or individual users' ```.rhosts``` files, along with a series of UNIX tools known collectively as r-commands. The ```/etc/hosts.equiv``` file contains a list of machine names or IP addresses that the system will trust (i.e, allow unauthenticated access of users from the given machine). 
- Similarly users can create a file called ```.rhosts``` in their home directories setting up trust between machines. 

The r-commands include :
- ```rlogin``` : a remote interactive command shell
- ```rsh```: a remote shell to execute one command
- ```rcp```: a remote copy command

Each of these commands allows for remote interaction with another machine. 

The r-commands are incredibly weak from a security perspective, as they base their actions on the IP address of the trusted machine and carry all information in clear text. 

Because of their weaknesses, the r-commands should be replaced with more secure tools for extending system trust, like the SSH tool, which provides for strong, cryptographic authentication and confidentiality. 


## Logs and Auditing
To detect attacks on a Linux or UNIX system, it is important to understand how various logging features work. In Linux and UNIX systems, event logs are created by the ```syslog``` daemon (known as ```syslogd```), a process that sits in the background and receives log information from various system and user processes, as well as the kernel. 
- The ```syslogd``` configuration is typically contained in the file ```/etc/syslog.conf```, which specifies where the log files are placed on the system. 
- Although particular Linux and UNIX flavors might store logs in different locations, the directory ```/var/log``` is a popular location for the logs. 

Some common log files of interest include the following:
- **Secure** (such as ```/var/log/secure```). This file contains information about successful and failed logins, including the user name and originating system used for login. Login records for applications such as telnet, rlogin, rsh, ftp, and so on are stored in this file. Different versions of Linux or UNIX might store this information under a different file name.
- **Messages** (such as ```/var/log/messages```). This file contains general messages from a variety of system components, including the kernel, specific modules, and daemons. It acts as a sort of catch-all for system logs.
- **Individual Applications** (such as ```/var/log/httpd, /var/log/cron``` and so on). Whereas some applications send their logs to a general log file (such as ```/var/log/messages```), others have specific log files. A common example is Web servers, which can be configured to log HTTP requests and other events to their own log files. 

The vast majority of log files in Linux and UNIX are written in standard ASCII and require root privileges for modification. 

To foil detection by system admins and users, as well as undermine forensics investigations, the following accounting files are of particular interest to attackers desiring to cover their tracks: 
- **utmp**: This file stores information about who is currently logged into a system. When a user or admin types the ```who``` command, the OS retrieves the contents of the utmp file to display who is logged in. A complete list of all users logged in is displayed, which is bad news for an attacker wanting to hide. Depending on the flavor of UNIX, this file can be stored in ```/var/run```, ```/var/adm```, or other locations. 
- **wtmp**: This file records all logins and logouts to and from the system. Depending on the flavor of Linux, this file can be stored in ```/var/log, /var/admn```, or other locations. The command ```last``` displays a list of all users that have logged in to the system, using the contents of ```wtmp```. 
- **lastlog**: The ```last``` log file contains information about the time and location of each user's last login to the system. On many Linux and UNIX systems, when a user logs in, the system consults the ```lastlog``` file to display a message. On many Linux systems, the ```lastlog``` file is located in ```/var/log/lastlog```. On some Linux variants, administrators can analyze the ```lastlog``` file using the ```lastlog``` command to see when each user last logged in and where they came from. 

# Common Linux and UNIX Network Services
To properly secure a system, you should deactivate or remove all services that are not explicitly required on the machine. 

## Telnet: Command-Line Remote Access
Telnet provides a command-line interface to a system remotely across the network.
- Users type in their user ID and password into a telnet client, which carries the information to a Telnet server
- On most Linux and UNIX systems, the telnet server (known as telnetd) is invoked by inetd or xinetd. 
- Standard telnet carries information unencrypted in plaintext
- Telnet sessions are extremely susceptible to session hijacking 

## FTP: File Transfer Protocol
FTP is used to move files between systems. Like telnet, FTP servers are typically started by inetd or xinetd, and all data is transmitted in clear text.
- Because FTP sessions are not encrypted, they can be easily captured by an attacker and even hijacked.

## A Better Way: Secure Shell (SSH)
The very sniff able and hijackable telnet and FTP services can be bad news from a security perspective. SSH is a better approach.
- The sshd program is typically started by init, and not inetd or xinetd.
- The SSH authentication can take place with a password, transmitted across the network in encrypted form. 

SSH clients and servers can communicate using two flavors of the SSH protocol: versions 1 and 2.
- The latter of these two is far more secure. 

SSH can also carry any TCP-based service in an encrypted fashion across the network using a technique called SSH port-forwarding. Using this technique, security can be added to many applications, riding across a rock-solid encrypted SSH tunnel. 

## Web Servers: HTTP
Web servers are used to send information to Web browsers using HTTP. The most popular Web server on Linux and UNIX today is the free Apache WEb server. 
- Web  servers are typically started by init
- Because they are often publicly accessible across the internet, web servers are frequent targets of attackers.

## r-Commands
As described earlier in this chapter, r-commands such as ```rlogin, rsh```, and ```rcp``` are sometimes used to interact remotely with Linux and UNIX systems. Each of these services is started by inetd or xinetd, and can offer an attacker an avenue for undermining Linux and UNIX trust relationships.

## Domain Name Servers
Clients use DNS servers to resolve domain names into IP addresses, among other capabilities. By far, the most popular DNS server on Linux and UNIX systems is the Berkeley Internet Name Domain (BIND) server, often called named. 
- DNS servers are usually started with init, and run in the background listening for requests. 

## The Network File System (NFS)
Linux and UNIX machines can share components of their file systems using the Network File System (NFS). NFS allows users to access file transparently across the network, making the remote directories and files appear to the user as though they were local.
- On the machine where the files to be shared are located, the NFS server exports various components of the file system (such as directories, partitions, or even single files). 
- Other machines can mount these exports at specific points in their file systems.

For example, one machine may export the directory ```/home/export``` so other machines can access the files in that directory. Another system can mount the exported ```/home/export``` directory onto its file system at the ```/mnt/files``` directory. A user on the second machine simply has to change directories to ```/mnt/files``` to access the remote files, without having to go through the explicit transfer of files that FTP would request. 

On most Linux and UNIX systems, ```mountd``` is responsible for handling mount requests. Once an exported directory is mounted, the ```nfsd``` daemon is the process that works with the kernel to ship the appropraite files across the network to NFS clients. 

Exporting files through NFS can be dangerous


## X Window System
The X Window System, known as X11 or even simply as X, provides the underlying GUI on most Linux and UNIX systems. An X server controls the screen, keyboard, and mouse, offering them up to various programs that want to display images or gather input from users. 
- One of the most commonly used X programs is the X terminal, which implements a command-line interface to run a command shell in a window on an X display. 

Attackers can abuse X in a variety of ways.
- To prevent such attacks, you should lock down your X displays using the ```xhost``` command or X magic cookies, which limit who can connect to your display and see the data on your screen.
- Going further you could tunnel all X Window traffic across an SSH session, giving you encryption and stronger authentication

 
# Summary

It is important to understand Linux and UNIX because they are so widely used on servers and workstations today. Because of its flexibility, relatively high performance, and power, many attackers also use it as a base from which to launch attacks. Many flavors of Linux and UNIX are available today, each with different features, programs, and controls.

Linux and UNIX are organized around their file systems. The top of the file system is the ```/``` directory, referred to as the "slash" directory. Under this directory, a variety of other directories include all system information. Important directories include the ```/etc```, which stores system configuration, as well as the ```/bin``` and ```/sbin```, which store important system executables

The kernel is the heart of Linux and UNIX operating systems, controlling all interaction with hardware and between running programs. When a program is executed, a process is created to contain its code, working memory, and various threads of execution. Processes can be started in a variety of ways. The init daemon starts processes during system boot-up. The inetd or xinetd program listens for incoming network traffic and starts processes to handle it. Cron starts processes at prespecified times. Manual user interaction also can start processes. The ```ps``` command provides a list of running processes on a system, and the ```lsof``` command provides a wealth of information with its list of all files opened by all processes. Users and admins can interact with processes by sending them signals using the ```kill``` and ```killall``` commands. The ```killall``` command must be used with care, because on Linux, it'll kill all processes with certain names. 

Accounts are defined with the ```/etc/passwd``` file. Some Linux and UNIX systems store passwords on the ```/etc/shadow``` file instead, which is a file only readable by accounts with super-user privilege's. Groups are defined in ```/etc/groups```. The root account has a UID of 0, and they too will have the same super-user privileges as the root account. 

Read, write, and execute permissions are assigned to each file in rwxrwxrwx format, where the first 3 characters refer to the file owner's permission, the second set of 3 characters refers to the owner group, and the third set of three characters applies to everyone on the machine with an account. The permissions can be altered with the ```chmod``` command. 

The ```ls``` command shows the contents of a directory with the ```-a``` option showing all files, whereas the ```-l``` option shows the long form of the output, including permissions associated with each file or directory.

SetUID capabilities allow a user to run a program with the permissions of the program's owner. Although essential for running a UNIX/Linux system, SetUID programs must be carefully guarded, as attackers frequently add or alter them. 

Event logs are created by the ```syslog``` daemon, which stores most logs in standard ASCII format. Accounting entries, such as who is currently logged in and when each user last logged in, are stored in the ```utmp, wtmp``` and ```lastlog``` files.

Most Linux/UNIX systems are prepackaged with a large number of network services active. Each of these services have security risks. Therefore all network services should be deactivated, except those that have an explicit business need on a machine. 

