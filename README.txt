##Usage

```
make all
./server.out
./client.out
```
The program has two executables to mimic a server / client
with two processes.

See the Makefile for compilation. The three .c files are
simply compiled into objects and then the server.o and client.o are
linked to the protocol.o object to create two executables

This makes two executables, server.out and client.out.

The server exacutable must be run before the client or
the client will timeout.

The client exacutable contains 14 example packets sent to
the server.

In order to reset the server's expected segment number,
 the server executable must be rerun. Running the client
 multiple times in a row without restarting the server will
 result in duplicate packet errors.

 Becuase assignment one and two are related, both are
 executed in the server and client executables.


##Assumption

* I assumed the client will never need to respond to the server's
messages. Thus the server never listens to responses.

* The Error Handling section states when a packet is rejected
 the server should send an error message to the client. I did
 this by sending a separate data packet to the client after a
 reject packet was sent. Unlike the other responses the client
 will only attempt once to receive this message.

* Because protocol does not define an end of segment
packet, the server's expected segment does not
reset without restarting the server (rerunning the
executable). All packets sent to the server (data and
access requests) are expected to have ordered segment
numbers.