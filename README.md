# DNS-Analysis-Using-AiEngine

Introduction of AIEngine (Artificial Intelligent Engine)
--------------------------------------------------------

AIEngine is a next generation interactive/programmable Python/Ruby/Java/Lua and Go network intrusion detection system engine with capabilities of learning without any human intervention, DNS domain classification, Spam detection, network collector, network forensics and many others. AIEngine also helps network/security professionals to identify traffic and develop signatures for use them on NIDS, Firewalls, Traffic classifiers and so on.

The main functionalities of AIEngine are:
----------------------------------------

- Support for interacting/programing with the user while the engine is running.
- Support for PCRE JIT for regex matching.
- Support for regex graphs (complex detection patterns).
- Support five types of NetworkStacks (lan,mobile,lan6,virtual and oflow).
- Support Sets and Bloom filters for IP searches.
- Supports x86_64, ARM and MIPS architecture over operating systems such as Linux, FreeBSD and MacOS.
- Support for HTTP,DNS and SSL Domains matching.
- Support for banned domains and hosts for HTTP, DNS, SMTP and SSL.
- Frequency analysis for unknown traffic and auto-regex generation.
- Generation of Yara signatures.
- Easy integration with databases (MySQL, Redis, Cassandra, Hadoop, etc...) for data correlation.

AIEngine Architecture
---------------------
The core of AIEngine is a complex library implemented on C++11/14 standard that process packets on real time. This library uses a external layer of high level programming languages, such as Python, Ruby or even Java, that brings to the engine the flexibility of this type of languages and the speed and performance of C++14 standard.


![aiengine_internal_architecture](https://user-images.githubusercontent.com/11352227/37080059-ebf2e6c4-220a-11e8-816d-3c11ff27d393.png)


How to Compile AiEngine for Python library
-------------------------------------

For compile the Python library is also recomended boost-python3-devel or boost-python-devel and python-devel.
 
The first option for compile the library is using O3 compile optimization, this will generate a small library

    $ git clone https://bitbucket.com/camp0/aiengine
    $ ./autogen.sh
    $ ./configure
    $ cd src
    $ make python
    $ python pyai_test.py

The second option will compile the library by using the standard pythonic way by using setup.py, this will generate
a bigger library size if compare with the previous one. 

    $ git clone https://bitbucket.com/camp0/aiengine
    $ ./autogen.sh
    $ ./configure
    $ cd src
    $ python setup.py build_ext -i 
    $ python pyai_test.py
    $ python3.6 setup.py build_ext -i 
    $ python3.6 pyai_test.py
   
Below bitbucket url providing complete description about AiEngine
-----------------------------------------------------------------
https://bitbucket.org/camp0/aiengine

 
