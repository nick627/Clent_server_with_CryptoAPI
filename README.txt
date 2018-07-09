# Clent_server_with_CryptoAPI

Distributed system for collecting information about workstations in the network.
The mechanism of interaction is "sockets".

A task:
Write a distributed system for collecting information about a computer, consisting of a server and a client interacting through sockets.

Requirements:
1. Develop the architecture of the system.
There is a computer network. There is a central computer to which information about all other computers on the network should be collected. The information should be collected in automatic mode. For this purpose, an agent is introduced on all computers, which is the server part of the system. On the central computer, the client part is started to request information. You must choose who initiates the transfer of information to the client or server; who is always working (ready to accept the request)  client or server; server stateless or statefull. Justify the proposed architecture.
2. Develop an application protocol for requesting and transmitting the following information about the system over the network:
Types of requests:
o type and version of the OS (GetVersionEx) (function names are given for an example);
o current time (GetSystemTime);
o time elapsed since the OS was launched (GetTickCount);
o information about the memory used (GlobalMemoryStatus) in megabytes;
o types of connected disks (GetDriveType) - local / network / removable, file system;
o free space on local disks (GetDiskFreeSpace) - definition of free disk space in gigabytes;
o access rights (in text form) to the specified file (folder), to the registry key (GetObjectAcl);
o owner of the file (folder), registry key (GetObjectOwner).
Requirements:
o use sockets (posix or WinSock, but not wrappers from MFC libraries or the like);
o there must be a separate request for each type of information;
o the answer format should be formalized and suitable for machine processing (and not just for visual perception by a person);
3. Develop a server program that, when launched, is able to respond to client requests on the developed protocol.
Requirements:
o Windows 7/8/10 all SP;
o console application without interactive user interaction;
o Diagnostic information is displayed on the console (connection / disconnection of clients, received and processed requests);
o a parallel query processing scheme (in the implementation, use the Win32 termination ports).
4. Develop a client program.
User interface requirements:
o the address of the server;
o Specifying the type of request;
o Initiating the request;
o output of the information sent by the server;
o the output format of the access rights must include the subject's SID, the subject name, the types of ACEs installed, the scope of the installed rights, the number of the installed bits in the access mask, the names of the installed bits for the current object type (in Russian or English or as constant names on MSDN) ;
o the output format of the owner of the object must contain the SID and the name of the owner;
o The current time and time elapsed since the OS was launched should be displayed in seconds, minutes, hours, days, etc .;
5. Implement encryption of transmitted data.
o all messages between the client and the server were transmitted in encrypted form, using CryptoAPI;
o data must be transmitted using one of the symmetric encryption algorithms with a session key;
o for the initial transfer of the session key, one of the asymmetric encryption algorithms must be used.
