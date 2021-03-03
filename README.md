# Raccoon P.I.

This repository contains a Python tool designed to aid in performing a very basic investigation on one or more IP Addresses.
This tool allows you to quickly perform a WHOIS lookup, Host lookup by IP address, IP Location lookup, and TOR node check in
one convenient spot. Results can be saved to either JSON or CSV format for lookups involving multiple IP addresses, individual
lookups are just displayed to the standard terminal output. All requested data will be parsed and stored in a series of Python
Dictionaries that can then be saved for later processing or the results can be viewed and filtered within this program before saving.

## Getting Started

This tool is optimized for Python 3.8x, and requires an up to date version of Python to properly function.

### Prerequisites

This program requires a few of things to work properly. First this is a Python tool optimized for Python 3.8x and above.
Secondly, in order to run the WHOIS lookup, the `whois` command line utility needs to be installed on your machine. Luckily,
on many modern systems this comes pre-installed. For instructions about how to download and install this program if it is
missing from your system, examine the instruction via one of the links below that matches the Operating System you're using:
WHOIS for: [Linux](https://www.howtogeek.com/680086/how-to-use-the-whois-command-on-linux/), [Mac OS](https://formulae.brew.sh/formula/whois), [Windows](https://docs.microsoft.com/en-us/sysinternals/downloads/whois). 
This tool will perform a WHOIS lookup and then, for multiple addresses, parse the data returned and allow you to export it
to either CSV or JSON format.
```
#  Basic WHOIS Response Format:
%   Misc. Unwanted Text

    KEY:    Value
    KEY:    Value

%    More Unwanted Text
```
Finally, in order to perform the TOR node check, where provided IP addresses are compared against a local list of known TOR Exit nodes,
a list of current exit nodes should be downloaded to your system and saved as a text file beforehand. The expected format of this
file consists of just a list of ip addresses each on a separate line. The required data can be downloaded in the correct format
from the following location [TOR Bulk Exit Node List](https://check.torproject.org/torbulkexitlist) and saved as `torbulkexitlist.txt`.
The name of this file will need to be provided when performing a TOR check.
```
# Download the list of TOR Exit nodes via curl:
$ curl -o torbulkexitlist.txt https://check.torproject.org/torbulkexitlist
```

## Python

Python 3 is essential for running this program and, while not required, I always suggest setting up a
python virtual environment (venv) or (pipenv) when running this tool in order to keep your workspace isolated.

If you already know you have an appropriate version of Python installed on your system, you can skip to either
Setting up a [Virtual Environment](#VirtualEnvironment), installing the [Requirements](#Requirements), or directly to [Usage](#Usage) 
if all the other Prerequisites have been met.

If you know you're missing Python3, you can find and download the appropriate package for your OS via the link below.
If you're unsure, or you have never installed Python before check out the next section about installing python.

* [Python.org](https://www.python.org/getit/) - Get Python 3.x here

## Installing Python

First check to see if Python is installed on your system and if so, what version is running. 
How that process works depends largely on your Operating System (OS).

### Linux

Note: Most Linux distributions come with Python preloaded, but it might not be with the latest version
 and you could only have Python 2 instead of Python 3 (which is what this program is written in).
 Double check your system's version by using the following commands:
```
# Check the system Python version
$ python --version

# Check the Python 2 version
$ python2 --version

# Check the Python 3 version
$ python3 --version
```

### Windows

In windows, open ‘cmd’ (Command Prompt) and type the following command.

```
C:\> python --version

```
Using the --version switch will show you the version that’s installed. Alternatively, you can use the -V switch:
```
C:\> python -V

```
Either of the above commands will give the version number of the Python interpreter installed or they will display an error if otherwise.

### Mac OSX

Starting with Catalina, Python no longer comes pre-installed on most Mac computers, and many older models only
have Python 2 pre-installed, not Python 3. In order to check the Python version currently installed on your Mac,
open a command-line application, i.e. Terminal, and type in any of the following commands:

```
# Check the system Python version
$ python --version

# Check the Python 2 version
$ python2 --version

# Check the Python 3 version
$ python3 --version
```
Note:
You’ll want to either download or upgrade to the latest version of Python if any of the following conditions are true:
* None of the above commands return a version number on your machine.
* The only versions you see listed when running the above commands are part of the Python 2.x series.
* Your version of Python 3 isn’t at least version 3.8x.

If Python is not already on your system, or it is not version 3.8x or above, you can find
detailed installation instructions for your particular OS, here:

Detailed instructions for installing Python3 on Linux, MacOS, and Windows, are available at link below:

* [Python 3 Installation & Setup Guide](https://realpython.com/installing-python/) - How to install Python3

## Package Management with pip

Once you have verified that you have Python 3.x installed and running on your system, you'll be using the built in
package manager 'pip' to handle the rest of the installations. 

pip is the reference Python package manager and is used to install and update packages. 
You’ll need to make sure you have the latest version of pip installed on your system.

### Linux

Note: Debian and most other distributions include a python-pip package. If, for some reason, you prefer to use 
one of the Linux distribution-provided versions of pip instead vist [https://packaging.python.org/guides/installing-using-linux-tools/].
 Double check your system's version by using the following commands:
```
# Check the system Python version
$ python -m pip --version

# Check the Python 3 version
$ python3 -m pip --version
```
You can also install pip yourself to ensure you have the latest version. It’s recommended to use the system pip to bootstrap a user installation of pip:
```
# Upgrade pip
$ python -m pip install --user --upgrade pip

# Upgrade pip python3
$ python3 -m pip install --user --upgrade pip
```

### Windows

The Python installers for Windows include pip. You should be able to see the version of pip by opening ‘cmd’ (the Command Prompt) and entering the following: 

```
C:\> python -m pip --version

```
You can make sure that pip is up-to-date by running:
```
C:\> python -m pip install --upgrade pip

```

### Mac OSX

 Double check your system's version by using the following commands:
```
# Check the system Python version
$ python -m pip --version

# Check the Python 3 version
$ python3 -m pip --version
```
You can also install pip yourself to ensure you have the latest version. It’s recommended to use the system pip to bootstrap a user installation of pip:
```
# Upgrade pip
$ python -m pip install --user --upgrade pip

# Upgrade pip python3
$ python3 -m pip install --user --upgrade pip
```

## VirtualEnvironment

It is recommended that you create a virtual environment in order to perform operations with this program on your system, 
this will need to be accomplished before installing any further dependencies this tool relies on.
The 'venv' module is the preferred way to create and manage virtual environments for this tool. 
Luckily since Python 3.3m venv is included in the Python standard library.
 Below are the steps needed to create a virtual environment and activate it in the working directory for this tool.

### Linux

To create a virtual environment, go to your project’s directory and run venv, as shown below:
```
# If you only have Python3 installed or Python3 is set as your default
$ python -m venv env

# If you have both Python2 and Python3 installed and want to specify Python3
$ python3 -m venv env
```

### Windows

To create a virtual environment, go to your project’s directory and run venv, as shown below: 

```
C:\> python -m venv env

```

### Mac OSX

To create a virtual environment, go to your project’s directory and run venv, as shown below: Double check your system's version by using the following commands:
```
# If you only have Python3 installed or Python3 is set as your default
$ python -m venv env

# If you have both Python2 and Python3 installed and want to specify Python3
$ python3 -m venv env
```

Note: The second argument is the location to create the virtual environment.
so accourding to the above commands: venv will create a virtual Python installation in the env folder.
In general, you can simply create this in your project yourself and call it env (or whatever you want).

Tip: You should be sure to exclude your virtual environment directory from your version control system using .gitignore or similar.

## Activating the Virtual Environment

Before you can start installing or using packages in your virtual environment you’ll need to activate it. Activating a virtual environment
erves to put the virtual environment-specific python and pip executables into your shell’s PATH.

### Linux

To create a virtual environment, go to your project’s directory and run venv, as shown below:
```
$ source env/bin/activate
```

### Windows

To create a virtual environment, go to your project’s directory and run venv, as shown below: 

```
C:\> .\env\Scripts\activate

```

### Mac OSX

To create a virtual environment, go to your project’s directory and run venv, as shown below: Double check your system's version by using the following commands:
```
$ source env/bin/activate
```
Now the development environment has been properly set up with an up to date version of Python 3 you're ready to install the required dependencies.


## Requirements

The main external library that this tool requires is the `resuests` module, which has its own prerequisites included below.
Included in this repository should be a 'requirements.txt' file, with the required libraries formatted as shown below.

```
certifi==2020.12.5
chardet==4.0.0
idna==2.10
requests==2.25.1
urllib3==1.26.3

```

To install these dependencies with via the 'requirements.txt' file, simply use  `pip -m install -r requirements.txt`

### Linux

Make sure the document 'requirements.txt' is in your current working directory and run:
```
$ python -m pip install -r requirements.txt
```

### Windows

Make sure the document 'requirements.txt' is in your current working directory and run: 

```
C:\> python -m pip install -r requirements.txt

```

### Mac OSX

Make sure the document 'requirements.txt' is in your current working directory and run:
```
$ python -m pip install -r requirements.txt
```


Once you have installed the few required dependencies, using this program is fairly straight forward.

## Usage

To begin you'll need to have at least one or more IP addresses that you wish to gather data on. If you are performing
multiple lookups from a file of addresses, make sure they are formatted correctly (i.e. with each address on a separate line).
You will also need to download a list of known TOR exit nodes if you wish to perform the TOR check. Instructions on one source
for this information and how to download it are included earlier in this document under [Prerequisites](#Prerequisites).
Once those conditions are met you are ready to begin using this tool.

Run `python raccoon.py` - as shown below there are also a set of optional arguments which are shown below:

```
usage: raccoon.py [-h] [-i [IP_ADDRESS]] [-m [MULTIPLE_IPS ...]] [-f [FILE_NAME]]
                  [-t [TOR_NODES]] [-o [OUTPUT_FILE]] [-d [DIR_OUT]] [-e [{CSV,JSON}]]
                  [-W] [-H] [-L] [-T] [-A] [-S]

Tool designed to aid in collecting information on provided IP addresses

optional arguments:
  -h, --help            show this help message and exit
  -i [IP_ADDRESS], --ip_address [IP_ADDRESS]
                        Input a single IP address that you wish to collect information
                        on
  -m [MULTIPLE_IPS ...], --multiple_ips [MULTIPLE_IPS ...]
                        Input multiple IP addresses from the command line to investigate
  -f [FILE_NAME], --file_name [FILE_NAME]
                        Input the file name that contains a list of IP addresses to
                        investigate
  -t [TOR_NODES], --tor_nodes [TOR_NODES]
                        Input file name that contains the known TOR exit nodes for local
                        check
  -o [OUTPUT_FILE], --output_file [OUTPUT_FILE]
                        Output file name where you want to save any results from the
                        investigation
  -d [DIR_OUT], --directory_out [DIR_OUT]
                        Set the name of the Directory to save the data collected on the
                        IP addresses
  -e [{CSV,JSON}], --export_type [{CSV,JSON}]
                        Select the type of file format you wish to export data to
                        (default=JSON)
  -W, --who_is          Signal that you want to perform a full WHOIS record lookup on
                        provided IPs
  -H, --host_lookup     Signal that you want to perform a host lookup by IP address on
                        the targets
  -L, --locate_ip       Signal that you want to retreive location data relating to the
                        target IPs
  -T, --tor_check       Signal that you want to check target IP(s) against known TOR
                        exit nodes
  -A, --alter_results   Signal that you wish to alter the results retrieved by filtering
                        out some data
  -S, --save_results    Signal that you wish to save the results from this program to
                        some file
```

If no arguments are specified upon running this program, the program will display the help menu seen above automatically.
The optional arguments shown above allow the user to 
 select the type of format (CSV or JSON) to convert your logs to ... 

### Examples
Upon the successful execution of the `raccoon.py` file, the results displayed to the
standard output should mimic what is shown below (with some differences based on the input supplied).

Below we pass the program a single IP address and signal (via `-WHLT`) that we want to perform the following:
`W`: WHOIS lookup, `H`: Host name lookup, `L`: IP location lookup, and `T`: TOR node check. 
Since we're performing the TOR check, we also pass the file name of our list of known TOR Exit nodes:

```
 $ python raccoon.py -WHLT -i 169.254.32.201 -t torbulkexitlist.txt

*** *** ***  Running 'raccoon.py'  *** *** ***

[*] Processing IP : '169.254.32.201'

[+] TOR Data IP: '169.254.32.201'
	source_ip:		169.254.32.201
	is_TOR:		False
	Target: '169.254.32.201', does not seem to be a known TOR Exit Node
	*** *** *** *** *** ***

[+] Host Data: '169.254.32.201'
	source_ip:		169.254.32.201
	host_name:		169.254.32.201.name.somecustomer.com
	host_alias:		['201.32.254.169.in-addr.arpa']
	host_address_list:		['169.254.32.201']
	*** *** *** *** *** ***

[+] Location Data: '169.254.32.201'
	source_ip:		169.254.32.201
	ip_country_code:		US
	ip_country_name:		United States
	ip_region_code:		AL
	ip_region_name:		Alabama
	ip_city:		SomeCity
	ip_zip_code:		00123
	ip_time_zone:		TimeZone
	ip_latitude:		38.9465
	ip_longitude:		-77.1589
	ip_metro_code:		404
	*** *** *** *** *** ***

[+] WHOIS Data: '169.254.32.201'
	source_ip:		169.254.32.201
	refer:		whois.net
	inetnum:		169.0.0.0 - 169.255.255.255
	organisation:		ORGName
	status:		ALLOCATED
	whois:		whois.net
	...:		...
	...:		...

	*** *** *** *** *** ***


*** *** *** *** *** *** *** *** ***

```

Here we're passing multiple IP addresses with the `-m` flag, signaling (via `-WHLTAS`) that we want to perform the following:
`W`: WHOIS lookup, `H`: Host name lookup, `L`: IP location lookup, `T`: TOR node check, `A`: alter results (i.e. edit the data), and `S`: save results. 
Since we're performing the TOR check, we also pass the file name of our list of known TOR Exit nodes and, since we're saving the results,
we also provide the name of the output file (with the `-o` flag) and the format we want to export the data to (i.e. `-e CSV`).
Note: since we used the `-A` flag, after the results are retrieved we are presented with a question about editing/viewing the data
answering 'yes' allows us to filter out some of the data before saving the results - answering 'no' skips this and saves the data.


```
 $ python raccoon.py -WHLTAS -m 169.254.32.201 169.254.115.52 169.254.29.83 -t torbulkexitlist.txt -o IP_Recon_Results -e CSV

*** *** ***  Running 'raccoon.py'  *** *** ***

[+] Processing IP : '169.254.32.201'

[+] Processing IP : '169.254.115.52'

[+] Processing IP : '169.254.29.83'

[?] Would you like to edit/view the results before saving? ['yes' or 'no']: yes

[?] Would you like to Select or Remove data ['Select' or 'Remove']: Select

[>] Valid Column Names:
[source_ip, Address, CIDR, City, Comment, Country, NetHandle, NetName, NetRange, NetType, OrgAbuseEmail, OrgAbuseHandle,
..., host_address_list, host_alias, host_name, inetnum, ip_city, ip_country_code, ip_country_name, ip_latitude, ip_longitude,
ip_metro_code, ip_region_code, ip_region_name, ip_time_zone, ip_zip_code, is_TOR, ..., whois]

[+] Please enter all the Columns from the above list (separated by a ',') to keep
	[->]: source_ip,ip_latitude,ip_longitude
[+] Saving only the following Columns: [source_ip, ip_latitude, ip_longitude]

[?] Would you like to view the results? ['yes' or 'no']: y

****** 169.254.32.201 *******

	source_ip:		169.254.32.201
	ip_latitude:		38.9465
	ip_longitude:		-77.1589

****** 169.254.115.52 *******

	source_ip:		169.254.115.52
	ip_latitude:		38.9518
	ip_longitude:		-77.1466

****** 169.254.29.83 *******

	source_ip:		169.254.29.83
	ip_latitude:		39.1090
	ip_longitude:		-76.7700

[?] Would you like to store these new results instead of originals? ['yes' or 'no']: yes

[?] Would you like to edit/view the results before saving? ['yes' or 'no']: no
[+] Exporting data to: IP_Data/IP_Recon_Results.csv

*** *** *** *** *** *** *** *** ***

```

Finally, below we're passing a file name containing multiple IP addresses with the `-f` flag.
Signaling (via `-WHLTS`) that we want to perform the following:
`W`: WHOIS lookup, `H`: Host name lookup, `L`: IP location lookup, `T`: TOR node check, and `S`: save results. 
Since we're performing the TOR check, we also pass the file name of our list of known TOR Exit nodes.
Since we're saving the results: we designate the directory where we want to results saved (`-d` flag),
provide the name of the output file (the `-o` flag) and the format we want to export the data to (`-e CSV`).

```
$ python raccoon.py -f target_IPs.txt -t torbulkexitlist.txt -e CSV -d ReconResults -o IP_Recon_Results -WHLTS

*** *** ***  Running 'raccoon.py'  *** *** ***

[+] Processing IP : '169.254.32.201'

[+] Processing IP : '169.254.115.52'

[+] Processing IP : '169.254.29.83'

[+] Processing IP :  ...

...				  :  ...

[+] Exporting data to: ReconResults/IP_Recon_Results.csv

```

Upon seeing output similar to the above, this program should be working as intended.


## Authors

* **Peter Robards** - *Initial work* - [PeterRobards](https://github.com/PeterRobards)

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details



