# tcplognke

    Last Revision: Version 1.3, 2006-11-27
    Build Requirements: Xcode 2.2 or later
    Runtime Requirements: OS X 10.4 or later

The tcplognke demonstrates the implementation of a network socket filter for processing incoming and outgoing http packets using the new Kernel Programming Interfaces provided in OS X 10.4.

The sample demonstrates the following:

1. use of the fine grain locking API's to serialize access to data queues,
2. the mbuf tag calls for tracking processing of mbufs by kernel extension code,
3. how the kernel process can "swallow" a packet and re-inject the packet at a later time,
4. the implementation of each of the intercept functions for a socket filter kernel process,
5. the use of the system control socket for communications between a kernel process and user level process,
6. produces a Universal Binary.
