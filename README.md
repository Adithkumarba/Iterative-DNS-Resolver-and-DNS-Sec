# Iterative-DNS-Resolver-and-DNS-Sec
Implementation of Iterative DNS Resolver and Resolver with DNS Sec using Python

- run the files using the command:

    python file_name arg1 arg2

- the mydig.py and dnssec.py takes 2 arguments:
    i) website name
    ii) rdtype

    eg :- python mydig.py paypal.com A

- The partC file will take a while to run as I have added a time.sleep() to prevent timeouts in the dns queries.
    If there is a dns timeout error. It is NOT a bug with the code. It is just the network error and is fixed by increasing timeouts.
    the output of the measurements is saved in the pdf and excel format, and also graph image is in the same folder.

- Libraries used:
    - dnspython
    - cryptography
    - pandas
    - matplotlib
    - tabulate
    Please install any missing libraries using pip install in case it shows module not found.
