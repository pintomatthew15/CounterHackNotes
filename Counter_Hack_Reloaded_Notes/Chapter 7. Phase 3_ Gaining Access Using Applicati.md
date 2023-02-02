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


# Summary
