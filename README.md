# wotftp

A one file transfer at a time write only TFTP server in Python 3.

The `wotftp` TFTP server only allows write requests (i.e. TFTP client `PUT` commands).
Any attempt to read a file will be rejected. Transfer can be requested in either ASCII or
binary but ASCII transfers will be treated as binary transfers.

The `--timestamp` command line option appends millisecond time stamps to the destination
file names on the server. As the server can only serve one request at a time and each transfer
is guaranteed to take at a minimum 2 milliseconds using this option makes it nearly
impossible for a transferred file to be overwritten - another copy is created with
a different timestamp.  See the section on the `--timestamp` command line option.

## Limitations

The limitations of the `wotftp` server are:

* Only one transfer at a time
* Only simple filenames supported (i.e. no subdirectories allowed)
* ASCII transfers treated the same as binary transfers

## Pre-requsites

You will need:

* A working Python 3 environment
* Administrator rights (for Windows) or root access (for UNIX/Linux)
* Well known TCP/IP port number 69 open for inbound and outbound UDP packets on the network interface you will use

## Running

At the command line type:

```
python wotftp.py
```

Depending on your environment you may need to type:

```
python3 wotftp.py
```

By default the `wotftp` server will copy transferred files to the current directory.
If you want to have the files copied to a different directory see the section on
the `--dir` command line argument.

## Supported characters in file names

Only file names which contain the following characters:

* Upper and lower case letters
* The digits 0 to 9 inclusive
* The full stop (period) character '.'
* The dash (hyphen) character '-'
* The underscore character '_'

are allowed. If this is too severe a restriction then amend the
function `validfilename` as appropriate.

## Command line argument `--dir`

The `--dir` command line option will copy transferred files to the directory
specified. For example:

```
python wotftp.py --dir c:\tftpboot
```

will cause all transferred files to be copied to the `c:\tftpboot` directory.

## Command line argument `--port`

By default TFTP transfers use well known TCP/IP port number 69.  If you want to
run the `wotftp` server on a different port number then use the `--port`
command line argument. For example:

```
python wotftp.py --port 8069
```

will use port number 8069.

## Command line argument `--bind`

By default the `wotftp.py` server will bind and listen on all available interfaces.
Sometimes you might only want it to bind to just one interface. Use the `--bind`
command line argument to do this. For example:

```
python wotftp.py --bind 10.1.1.100
```

will bind and listen on the interface with IPv4 address 10.1.1.100 and only that
interface.

## Command line argument `--remoteip`

By default the `wotftp.py` server will accept connections from any
remote client. If you only want to accept connections from a single
remote client then use the `--remoteip` command line argument. For example:

```
python wotftp.py --remoteip 10.1.1.5
```

will only allow connections from the remote client with IPv4 address 10.1.1.5
while requests from any other client will be ignored.

## Command line argument `--timestamp`

When the `--timestamp` command line argument is specified each file transferred
has a timstamp appended to the filename on the server. For example a file called:

```
file.txt
```

will be stored on the server with a file name similar to:

```
file.txt-2020-04-20-11-05-37-345
```

The timestamp is made up of year, month, day, hour, minute, second and millisecond.

When the `--timestamp` command line option is used the `wotftp` TFTP server will
sleep for a period of 2 milliseconds after receiving a valid write request. This
helps ensure no file ever gets accidently or maliciously overwritten. This is not
fullproof, however, think about what happens if the system clock goes back for
example.

## Command line argument `--ipstamp`

When the `--ipstamp` command line is specified each file
transferred has the remote client IPv4 address prepended to the filename on the server.
For example a file called:

```
file.txt
```

will be stored on the server with a file name similar to:

```
10.1.1.5-file.txt
```

Note that the `--ipstamp` and `--timestamp` command line arguments can be
used together.  This will result in file names like:

```
10.1.1.5-file.txt-2020-04-20-11-05-37-345
```

on the server.

## Command line argument `--verbose`

By default the `wotftp` server has a verbose level of 1. Valid values for
the `--verbose` command line argument are 0, 1 and 2. 0 means only display serious error messages.
1 means display a moderate amount of information. 2 means show alot of information.

At verbose levels 1 and 2 the server issues a message similar to:

```
Idle at 11:38:42
```

when the server has been idle for approximately 10 seconds.

## Stopping the `wotftp` server

Once started the `wotftp` server runs forever. If started from the command line
it can be stopped by typing the `Control^C` character sequence. If it is running as
a background process then use the appropriate process termination method
for your environment.

## Notes on security

The TFTP protocol is insecure. It is insecure in two ways:

* Data is not encrypted when it is sent between client and server
* No user, password or any form of authentication is performed

One way to get around the data not being encrypted is to encrypt each file
before it is sent.

No authentication is, in my opinion, one of TFTP's strengths as files can
be sent to a TFTP server using a script or other program and there is no
need to store sensitive user names and passwords. The one draw back is
that once a file has been written to a TFTP server another client
could accidentally or maliciously send other data and overwrite the file.
This is one of the reasons for the `--timestamp` command line option
for the `wotftp` server. At least the original good file would exist
on the server with a slightly older timestamp.

If security is an issue then use another file transfer protocol that meets
the specific needs. The `wotftp` server is just one implementation
for simpler needs.

## References

The section on TFTP from the excellent online TCP/IP guide by Charles M. Kozierok:

[Trvial File Transfer Protocol (TFTP)](http://www.tcpipguide.com/free/t_TrivialFileTransferProtocolTFTP.htm)

has everything you need to know about the operation of TFTP and the packet formats.

## To do list

Come up with a way to gracefully stop the `wotftp` server. One idea would be to send
a certain `magic` packet to the server.

Enhance the code so it can handle multiple write requests from more than one
client at a time.

--------------------------------------------------------

End of README.md
