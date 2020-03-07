UCLA CS118 Project (Simple Router)
====================================


## Project Team

- Bowen Zhang, UID 905322977. Contributions include IP prefix lookup code and
  the initial code skeleton for IP-packet handling. Special thanks are given
  due to his dogged persistence when hunting the bugs nobody else could. 
- Varun Pidugu, UID 704961666. Contributions include ARP cache management and
  ARP-request sending code. 
- Yash Lala, UID 905159212. Contributions include Ethernet-frame handling code,
  ARP-request handling code, ICMP-handling code, rewriting IP-packet code,
  ARP-IP-packet-flushing code, and this README. 

Remaining contributions can be found in the commit history. 


## High-Level Design

The design of this code does not deviate in any meaningful way from the
skeleton code provided. The code functions as follows: 

1. When it receives a packet, the router: 
   - Checks if it is an ARP reply, and updates its cache accordingly. 
   - Checks if it is an IP packet destined for the router, in which case it
     either responds to a ping request or returns an ICMP Not Reachable packet.
   - Checks if it is an IP packet destined for another IP, in which case it
     looks up the packet and forwards it to the appropriate interface. If the
     destination MAC address is unknown, it sends out an ARP request, then
     flushes the outbound packet queue when interpreting the response. 
2. While undertaking other actions, the router keeps track of IP->MAC address
   associations for each interface in a cache table. When a cache entry becomes
   stale, it is removed from the queue. 

While some code is duplicated, the code is functional and (as far as the writer
knows) bug free *given certain assumptions* about incoming packets. 


## Problems Encountered

This project involved a lot of bugs and associated bug fixing. Mininet was
notoriously uncooperative; even the final version of this project
intermittently fails given certain factors, including (but not limited to): 

1. The timings of the `./router` and `./run.py` commands. 
2. Mininet's 'freshness'; ie. if it has been run before in the container. 
3. Mininet's mood. 
4. The alignment of the moons of Jupiter. 

In order to deal with these challenges, we attempted to coordinate our work in
a way that would minimize redundant code and fixes. We did so by using Git to
coordinate our feature branches and fixes. While not all of us knew how to use
version control at the beginning (and arguably may not know so now), we managed
to get a workflow that allowed us to quickly coordinate changes and allow for
independent work. 

While it may sound hand-wavey to claim 'expedient communication' was our only
real method when solving problems, we claim that a project of this size really
required nothing more. When we were running close on time, we split our teams
as per their strengths. Those new to C/C++ programming spent their time
reporting logic errors (the writer would once again like to thank Bowen,
without whom this project would still be a buggy mess), while those new to
remaining patient opted to spend their time coding the described fixes and
features. 

GDB was not particularly useful due to an unexpected permissions error, so most
of our debugging was done through the tried-and-true `printf` method. 


## Makefile

The provided `Makefile` provides several targets, including to build `router`
implementation. Additionally, the `Makefile` contains a `clean` target, and
`tarball` target to create the submission file as well.

For build dependencies, please refer to [`Vagrantfile`](Vagrantfile).


## Known Limitations

When POX controller is restarted, the simpler router needs to be manually
stopped and started again. In addition, the code may fail when responding to
certain oddly formed IP packets (although this is not expected to occur during
the program's operation). 


## Acknowledgement

This implementation is based on the original code for Stanford CS144 lab3
(https://bitbucket.org/cs144-1617/lab3).
