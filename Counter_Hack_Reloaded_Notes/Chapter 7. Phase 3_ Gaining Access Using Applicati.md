# Notes
At this stage of the siege, the attacker has finished scanning the target network, developing an inventory of target systems and potential vulnerabilities on those machines. Next, the attacker wants to gain access on the target systems. The particular approach to gaining access depends heavily on the skill level of the attacker, with simple script kiddies trolling for exploits and more sophisticated attackers using highly pragmatic approaches.

# Script Kidde Exploit Trolling
To gain access, the average script kiddie typically just takes output from a vulnerability scanner and surfs to a Web site offering vulnerability exploitation programs to the public. 

Web sites offering large databases chock full of exploits include:
- Packet Storm Security
- The Metasploit Project

Although this indiscriminate attack technique fails against well-fortified systems, it is remarkably effective against huge numbers of machines on the Internet with system administrators who do not keep their systems patched and configured securely. 

# Pragmatism For More Sophisticated Attackers
Phase 3, of the five step attack process described in this book tends to be very free-form in the hands of a more sophisticated attacker. 
- Although the other phases of the attack are more systemic, the techniques used to gain access depend heavily on the architecture and configuration of the target network, the attacker's own expertise and predilections, and the level of access with which the attacker begins.
- There is no clearly defined order for this phase of the attack, so techniques discussed in this chapter can happen in any configuration. 

# Buffer Overflow Exploits
Buffer overflows are extremely common today, and offer an attacker a way to gain access to and have a significant degree of control over a vulnerable machine.
- Read "Smashing the Stack for Fun and Profit" - By Aleph One

Buffer overflow vulnerabilities are based on an attacker sending more data to a vulnerable program than the original software developer planned for when writing the code for the program. The buffer that is overflowed is really just a variable used by the target program. 
- In essence, these flaws are a result of sloppy programming, with a developer who forgets to create code to check the size of user input before moving it around in memory. 
- Based on this mistake, an attacker can send more data than is anticipated and break out of the bounds of certain variables, possibly altering the flow of the target program or even tweaking the value of other variables. 

## Stack-Based Buffer Overflow Attacks
Right now, if your computer is booted up, it is processing millions of computer instructions per second, all written in machine language code. The figure below highlights the relationship of a system's processor and memory during execution. 

![50dfdaeb85a4bdf78be3be4c8655e6bf.png](../_resources/50dfdaeb85a4bdf78be3be4c8655e6bf.png)\

When you run a program, your machine's Central Processing Unit (CPU) fetches instructions from memory, one by one, in sequence. The whole program itself is just a bunch of bits in the computer's memory, in the form of a series of instructions for the processor. The CPU contains a very special register called the instruction pointer, which tells it where to grab the next instruction for the running program. 
- After the CPU executes an instruction, the instruction pointer is incremented to point to the next instruction
- When a jump or branch is encountered, the instruction pointer's value is altered to point to the new location in memory, where sequential fetching of instructions begins anew. 

### Function Calls and the Stack
Most high-level languages include the concept of a function call, used by programmers to break the code down into smaller pieces. The figure below shows some sample code written in the C programming language. 

![41a08d99c592d16a50f11ef8a63216ff.png](../_resources/41a08d99c592d16a50f11ef8a63216ff.png)

When the program starts to run, the ```main``` procedure is executed first. The first thing the ```main``` procedure does is to call our sample function. All processing by the program will not transition from the ```main``` procedure to the sample function.

The system has to remember where it was operating in the ```main``` procedure, because after ```sample_function``` finishes running, the program flow must return back to the main procedure. The system uses a stack to remember this information associated with function calls.

A stack is a data structure that stores important information for each process running on a computer. The stack acts kind of like a scratch pad for the system.
- They behave like a stack of dishes (last in, first out (LIFO))
- When a computer puts data onto its stack, it pushes data element after data element on the stack. When it needs to access data from the stack, the system first takes off the last element it placed on the stack, a process known as popping an item off the stack.

Stacks store information associated with function calls. As shown in the figure below, a system pushes various data elements onto the stack associated with making a function call.

![d42104d3a3c15df568262596a908972b.png](../_resources/d42104d3a3c15df568262596a908972b.png)

First, the system pushes the function call arguments onto the stack. This includes any data handed form the main procedure to the function
- To keep things simple, the example code in Figure 7.3 included no arguments

Next, the system pushes the return pointer onto the stack. This return pointer indicates the place in the system's memory where the next instruction to execute in the main procedure resides
- For a function call, the system needs to remember the value of the instruction pointer in the main procedure so that it knows where to go back to for more instructions after the function finishes running 
- The Instruction pointer is copied onto the stack as a return pointer

Next, the system pushes the Frame Pointer on the stack. This value helps the system refer to various elements on the stack itself. 

Finally, space is allocated on the stack for the local variables that the function will use. In our example, we've got one local variable called ```buffer``` to be placed on the stack. These local variables are supposed to be for the exclusive use of the function, which can store its local data in them and manipulate their values. 

After the function finishes running, printing out its happy message of "Hello World", control returns to the main program. 
- This transition occurs by popping the local variables from the stack (in our example the ```buffer``` variable). 
- The Stack pointer now moves down to its value before the function was called
- The saved Frame Pointer is also removed from the stack and squirreled away in the processor
- Then the return pointer is copied from the stack and loaded into the processor's Instruction Pointer register

Finally, the function call arguments are removed, returning the stack to its original (pre-function-call) state.

### What is a Stack-Based Buffer Overflow?
Consider the sample vulnerable program below
![a190a3053a1ab712ae3ce1cb08f66a9b.png](../_resources/a190a3053a1ab712ae3ce1cb08f66a9b.png)

For this program, the main routine prints a "Hello World!" greeting and then calls the ```sample_function```. In ```sample_function```, we create two buffers, ```bufferA```, which holds 50 characters and ```bufferB```, which holds 16 characters. Both of these are local variables of the ```sample_function```, so they will be allocated space on the stack as shown in the figure below
![93f373b00ed8d60cfa24b420127601c4.png](../_resources/93f373b00ed8d60cfa24b420127601c4.png)

We then prompt the user for input by printing "Where do you live?" The ```gets``` function from a standard C library will pull input from the user. 

Next we encounter the ```strcpy``` library call. This routine is used to copy information from one string of characters to another. In our program, ```strcpy``` moves characters from ```bufferA``` to ```bufferB```

There are a couple problems with the code as presented:
1. The ```gets``` library puts no limitation on the amount of data a user can type in, if the user types in more than 50 characters, ```bufferA``` will be overflowed, letting the attacker change other nearby places on the stack. 
2. The ```strcpy``` library call is also very sloppy, because it doesn't check the size of the either string, and happily copies from one string to the other until it encounters a null character in the source string. 
3. So even if the attacker doesn't overflow ```bufferA``` with more than 50 characters of user input in the ```gets``` call, the attacker has a shot at overflowing ```bufferB``` simply by typing between 17 and 50 characters into ```bufferA```, which will be written to ```bufferB```. 

The attacker's input will run through both buffers and spill into other parts of the program. If the attacker can overwrite the return pointer which is located below the local variables and saved Frame Pointer, they can inject their own malicious shellcode. 
- **The attack could overwrite the return pointer with a value that points back into the buffer, which contains the commands he or she wants to execute**

The resulting recipe, as shown in the figure below, is a stack-based buffer overflow attack, and will allow the attacker to execute arbitrary commands on the system. 
![1bd9bc415b12b91268751ab1e199fe5b.png](../_resources/1bd9bc415b12b91268751ab1e199fe5b.png)

Focusing on just cramming too much input into ```bufferA``` via that vulnerable ```gets()``` call. The attacker gets a program to fill one of its local variables (a buffer) with data that is longer than the space allocated on the stack, overwriting the local variables themselves with machine language code. 
- The system doesn't stop at the end of the local variables
- It keeps writing data over the end of the buffer, clobbering the saved Frame Pointer, and even overwriting the return pointer with a value that points back to the machine language instructions the attacker loaded into the ```bufferA``` on the stack. 

When the function calls finishes, the local buffers containing the instructions will be popped off the stack, but the information we place in those memory locations will not be cleared. 
- The system then loads the now-modified return pointer into the processor, and starts executing instructions where the return pointer tells it to resume execution.
- The processor will then start executing the instructions the attacker had put into the buffer on the stack. 

This whole problem is the result of a developer not checking the size of the information he or she is moving around in memory when making function calls. 

The most useful thing an attacker can place on the stack is a command shell, because then the attack can feed the command shell (such as the UNIX and Linux /bin/sh or Windows cmd.exe) any other command to run. 
- This can be achieved by placing the machine language code for executing a command prompt in the user input. 
- Most OSs include an exec system call to tell the operating system to run a given program. 
- Some attackers force their shell to make a connection to a given TCP or UDP port, listening for the attacker to connect and get a remote command prompt. 
- Others prefer to add a user to the local administrator's group on behalf of the attack. Still other attackers might force the shell to install a backdoor program on the victim system.

Alternatively, instead of invoking the attacker's code in the stack, the attacker could change a return pointer so that it doesn't jump into the stack, but instead resumes execution at another point of the attacker's choosing.
- Some attackers clobber a return pointer so that it forces the program to resume execution in the heap, another area of memory we discuss a little later.
- Or the attacker could have the program jump into a particular C library the attacker wants to invoke, a technique known as "return to libc" attack

It is important to note that an attacker's program will run with the permissions of the vulnerable program. 

Buffer overflow attacks are very processor and operating system dependent, because the raw machine code will only run on a specific processor, and techniques for executing a command shell differ on various operating system.

## Exploiting Stack-Based Buffer Overflows
To exploit a buffer overflow, an attacker enters data into the program by typing characters into a GUI or command line, or sending specially formatted packets across the network. 
- In this input to the program, the attacker includes the machine language code and new return pointer in a single package.
- If the attacker sends just the right code with just the right return pointer formatted just the right way to overflow a buffer of a vulnerable program, a function in the program will copy the buffer to the stack and ultimately execute the attacker's code

## Finding Buffer Overflow Vulnerabilities
Other C and C++ functions that often cause such problems include the various string and memory handling routines like these:
- ```fgets```
- ```gets```
- ```getws```
- ```sprintf```
- ```strcat```
- ```strcpy```
- ```strncpy```
- ```scanf```
- ```memcpy```
- ```memmove```

Beyond these function calls, the developer of the program might have created custom calls that are vulnerable. Some exploit developers reverse engineer executables to find such flaws

Alternatively, exploit creators might take a more brute force approach to finding vulnerable programs. They sometimes run the program in a lab and configure an automated tool to cram massive amounts of data into every input of the program. The program's local user input fields, as well as network inputs, will be inundated with data.

Exploit creators are looking for a program to crash under this heavy load of user input, but to crash in a meaningful way. They'd like to see their repeated input pattern (like the character A, which in hex is 0x41) reflected in the instruction pointer when the program crashes. 
- This technique of varying the user input to try to make a target system behave in a strange fashion is sometimes called fuzzing

Consider this example of the output dump of a debugger showing the contents of a CPUs registers when a fuzzer trigger an overflow using a bunch of A characters
![50ed41dbb11367e43820271ab51ce873.png](../_resources/50ed41dbb11367e43820271ab51ce873.png)

Glancing at the instruction pointer (EIP), we see the series of long A's represented through its hex of 0x41 meaning we have overflowed the buffer through user input and reached the return pointer and then transferred into the instruction pointer. 

Once the attackers find out that some of the user input made it into the instruction pointer, they need to figure out which part of all those As was the element that landed on the return pointer. 

They determine this by playing a little game. 
- They first fuzz with all A's as we saw before.
- Then, they fuzz with an incrementing pattern, perhaps all of the ASCII characters, including ABCDEF and all other characteres repeated again and again. 
- They then wait for another crash. Now, suppose the attacker sees that DEFG is in the return pointer slot. The attacker then fuzzes with each DEFG pattern of the input tagged, such as DEF1, DEF2, DEF3, and so on. 
- Finally, the attacker may discover that DEF8 is the component of the user input that hits the return pointer.
- The attacker now knows where in the user input to place the return pointer. 

Automated tools exist, which can play this game, which will identify the location in the user input where the new return pointer should be placed. 

Because the stack is very dynamic, it can be difficult to find the exact location of the start of the executable code the attacker pushes onto the stack. 
- To address this dilema, the attacker usually prepend their machine language code with a bunch of No Operation (NOP) instructions. Most CPUs have one or more NOP instruction types, which tell the processor to do nothing for a single clock cycle. 
- By putting a large number of NOP instructions at the beginning of the machine language code, the attacker improves the odds that the guess return pointer will work.
- As long as the guessed address jumps back into the NOP sled somewhere, the attacker's code will execute. 

The code will do nothing, nothing, nothing, and then run the attcker's code to exec a shell. 

You can think about the value of a NOP sled by considering a dart game. When you throw a dart at the target, you'd obviously like to hit the bull's eye.
- The guess of the return pointer is something like throwing a dart. If you guess the proper location of the start of the machine language code on the stack, that code will run
- Otherwise the program will crash, something akin to your dartboard exploding
- A NOP sled is like a cone placed around the bull's eye on the dartboard. As long as your dart hits the cone (the NOP sled), the dart will slide gently into the bull's eye and you'll win the game.

Attackers prepend as many NOP instructions at the front of their machine language code as they can, based on the size of the buffer itself. 
- If the buffer is 1,024 characters long, and the machine language code takes up 200 bytes, that leaves 824 characters for NOPs. 
- Bigger buffers ironically only make it easier to attack a program with a buffer overflow exploit.

The NOP instructions used by an attacker in the NOP sled could be implemented using the standard NOP instruction for the given target CPU type, which might be detected by an IDS when a large number of NOPs move across the network. 
- Craftier attackers might choose a variety of different instructions that, in the end, still do nothing, such as adding zero to a given register, multiplying a register by one, or jumping down to the next instruction by memory.

As we have seen, the fundamental package for a buffer overflow exploit created by an attacker consists of three elements:
1. A NOP sled
2. Machine language code designed to exec a shell
3. A return pointer to make the whole thing execute

The structure of a common buffer overflow exploit is shown below:
![4d0d2b88f24ee661da86ee536e7f55c4.png](../_resources/4d0d2b88f24ee661da86ee536e7f55c4.png)


## Heap Overflows
So far, our analysis of buffer overflow flaws has centered on the stack, the place where a process stores information associated with function calls. However, there's another form of buffer overflow attack that targets a different region of memory: the heap. 
- The stack is very organized, in that data is pushed onto the stack and popped off of it in a coordinated fashion in association with function calls, as we've seen.

The heap is quite different. Instead of holding function call information, the heap is a block of memory that the program can use dynamically for variables and data structures of varying sizes at runtime. 
- Suppose you are writing a program and want to load a dictionary in memory.
- In advance, you have no idea how big that dictionary might be. 
- Using the heap, you can dynamically allocate memory space as your program reads different dictionary terms as it runs.
- The ```malloc``` library call is the most common way to allocate space in the heap. It is short for memory allocation, and this function grabs some space from the heap so your program can tuck data there.

If a developer uses ```malloc``` to allocate space in the heap where user input will be stored, but again forgets to check the size of the user input, we will get a heap-based overflow vulnerability. To illustrate this concern refer to the figure below. 
![4169b2d4cc4d1f49ac79c7b8bfa35e20.png](../_resources/4169b2d4cc4d1f49ac79c7b8bfa35e20.png)

Our program starts to run and creates some pointers where we'll later allocate memory to hold a user's color preference and name, called ```color_pref``` and ```user_name```, respectively. 

We then use the ```malloc``` call to allocate tne characters in the heap to each of these variables. The heap typically grows in the opposite directoin as the stack in most OS and processors.

Next, our program uses the ```strncpy``` call, wich copies a fixed number of characters into a string. We copy into the ```user_name``` a fixed value of "fred", only four characters in length. This ```user_name``` is hard coded, and shouldn't be alterable by the user in any way.

Next, we quiz our user, asking his or her favorite color. Note that the users used the ```gets``` function to load the user input into the ```color_pref``` variable on the heap.

The program finishes by displaying the user's favorite color and user name on the screen. 

![a94522aa17d891f40b6f49b044dad5f6.png](../_resources/a94522aa17d891f40b6f49b044dad5f6.png)

To see what happens when this program runs, consider the figure below, which shows two sample runs of the program.
- In the first run the user types a favorite color of blue. the program prints out a favorite color of blue and a user name of fred.
- For the next run, the user is an evil attacker, who types in a favorite color of blueblueblueblueroot. That's 16 characters of blue followed by root/

Because the developer put no limitation on the size of the user input with that very lame ```gets``` call, the bad guy was able to completely overwrite all space in the ```color_pref``` location on the heap, breaking out of it and overwriting the ```user_name``` variable with the word root!
- This would not change the User ID of the running program itself in the OS, but it would allow the attacker to impersonate another user named root within the program itself.

Note that the attacker has to type in more than just ten characters (in fact, 16 characters are required, as in blueblueblueblue) to scoot out of the ```color_pref``` variable.
- That's because the ```malloc``` call sets aside a little more space than we ask for to keep things lined up in memory for itself. 

![3adb28b4d04ffee6d4095556743d8483.png](../_resources/3adb28b4d04ffee6d4095556743d8483.png)

## The Exploit Mess and the Rise of Exploitation Engines
There was a huge surge in exploits developed for these systems and script kiddies ran wild with them. 

The quality of individual exploit scripts varied greatly. Some exploit developers fine-tuned their wares, making them highly reliable in penetrating a target

To help tame this mess of different exploits, Metasploit was related. Metasploit is an exploit framework for the development and use of modular exploits to attack systems, available for free. 
- It is written in Pearl and runs on Linux, BSD, and Microsoft Windows

In a sense, Metasploit and these commerical tools act as an assembly line for the mass production of exploits, doing about 75 percent of the work needed to create a brand new, custom exploit. 

Exploit frameworks are not simply another take on vulnerability scanners. 
- A vulnerability scanner attempts to determine if a target machine has a vulnerability present, simply reporting on whether or not it thinks the system could be subject to exploitation. 
- An exploit framework goes further, actually penetrating the target, giving the attacker access to the victim machine. 

To understand how Metasploit works, let's look at its different parts, as shown in the figure below. 
- First, the tool holds a collection of exploits, little snippets of code that force a victim machine to execute the attacker's payload, typically by overwriting a return pointer in a buffer overflow attack.

![291ac76100ef6dbb2156ea9be66bfc6c.png](../_resources/291ac76100ef6dbb2156ea9be66bfc6c.png)

Next, Metasploit offers a huge set of payloads, that is, code the attacker wants to run on the target machine, triggered by the exploit itself. An attacker using Metasploit can choose from any of the following payloads to foist on a target:

- **Bind Shell to Current Port**: This payload opens a command shell listener on the target machine using the existing TCP connection of a service on the machine. The attacker can then feed commands to the victim system across the network to execute at a command prompt.
- **Bind Shell to Arbitray Port**: This payload opens a command shell listener on the target machine using the existing TCP connection of a service on the machine. The attacker can then feed commands to the victim system across the network to execute at a command prompt.
- **Reverse Shell**: This payload shovels a shell back to the attacker on a TCP port. With this capability, the attacker can force the victim machine to initiate an outbound connection, sent to the attacker, polling the bad guy for commands to be executed on the victim machine. So, if a network or host-based firewall blocks inbound connections to the victim machine, the attacker can still force an outbound connection from the victim to the attacker, getting commands from the attacker for the shell to execute. The attacker will likely have a Netcat listener waiting to receive the shoveled shell.
- **Windows VNC Server DLL Inject**: This payload allows the attacker to control the GUI of the victim machine remotely, using the Virtual Network Computing (VNC) tool sent as a payload. VNC runs inside the victim process, so it doesn't need to be installed on the victim machine in advance. Instead it is inserted as a DLL inside the vulnerable program to give the attacker remote control of the machine's screen and keyboard.
- **Reverse VNC DLL Inject**: This payload inserts VNC as a DLL inside the running process, and then tells the VNC server to make a connection back to the attacker's machine, in effect shoveling the GUI to the attacker. That way, the victim machine initiates an outbound connection to the attacker, but allows the attacker to control the victim machine.
- **Inject DLL into Running Application**: This payload injects an arbitrary DLL of the attacker's choosing into the vulnerable process, and creates a thread to run inside the DLL. Thus, the attacker can make any blob of code packaged as a DLL run on the victim.
- **Create Local Admin User**: This payload creates a new user in the administrators gorup with a name and password specified by the attacker. 
- **The Meterpreter**: This general-purpose payload carries a very special DLL to the target box. This DLL implements a simple shell, called the Metasploit Interpreter, or Meterpreter for short, to run commands of the attacker's choosing. However, the Meterpreter isn't just a tool taht executes a separate shell process on the target. On the contrary, this new shell runs inside of the vulnerable program's existing process. It's power lies in 3 aspects
	1.  First, the Meterpreter does not create a separate process to execute the shell (such as cmd.exe or /bin/sh would) but instead runs it inside the exploited process.
	2.  Second, the Meterpreter does not touch the hard drive of the target machine, but instead gives access purely by manipulating memory. Therefore, there is no evidence left in the file system for investigators to locate. 
	3.  Third, if the vulnerable service has been configured to run in a limited environment so that vulnerable program cannot access certain commands on the target file system (known as the chroot environment), the Meterpreter can still run its built-in commands within the memory of the target machine, regardless of the chroot limitation. 

To support a user in selecting an exploit and payload to launch at a target, Metasploit includes 3 different user interface options: 
1. A command-line tool suitable for scripting
2. A console prompt with specialized keywords
3. A point-and-click Web interface accessible via a browser (see figure below)
![9840b45f3edf3f51212815f746c212bc.png](../_resources/9840b45f3edf3f51212815f746c212bc.png)

In addition to the exploits and payloads, Metasploit also features a collection of tools to help developers create brand new exploits and payloads. 
- Some of these tools review potentially vulnerable programs to help find buffer overflow and related flaws in the first place
- Others help the developer figure out the size, location, and offset of memory regions in the target program that will hold and run the exploit and payload, automating the ABCDEF game discussed earlier.
- Some of the exploit development support tools include code sampels to inject a payload into the target's memory, and still others help armor the resulting exploit and payload to minimize the chance it will be detected or filtered at the target.

## Advantages For Attackers
Exploit frameworks like Metapsloit offer significant advantages for the bad guys, including those who craft their own exploits and even the script kiddies just looking for low-hanging fruit. 
- For the former, exploit frameworks shorten the time needed to craft a new exploit and make the task a lot easier
- They have also increased the quality of exploit code, making the bad guys a lot more lethal.

## Benefits For the Good Guys Too?
Exploit frameworks aren't just evil. Tools like Metasploit can also help security professionals to improve our practices as well. 
- One of the most valuable aspects of these tools to infosec pros invovles minimzing the glut of false positives from our vulnerability-scanning tools.
- Chief Information Security Officers (CISOs) and auditors often lament the fact that many of the high-risk findings discovered by a vulnerability scanner turn out to be mere fantasies, an error in the tool that thinks a system is vulnerable when it really isn't. 
- Such false positivies sometimes comprise 30 to 50 percent or more of the findings of an assessment. 

Metasploit can help alleviate this concern. After the assessment team runs the vulnerability scanner and generates a report they can run an exploit framework for each of the vulnerabilities they find to verify the presence of the flaw. 
- The Metasploit framework can give a really high degree of certainity that the vulnerability is present, because it lets the test gain access ot the target machine. 

## Buffer Overflow Attack Defenses
There are a variety of ways to protect your systems from buffer overflow attacks and related exploits. These defensive strategies fall into the following two categories:
1. Defenses that can be applied by system administrators and security personnel during deployment, configuration, and maintenance of systems
2. Defenses applied by software developers during program development 



# Summary
