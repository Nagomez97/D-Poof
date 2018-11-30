# D-Poof
A python-based DNS spoofer

This is a Python-Scapy based DNS spoofer. You will be able to perform a MITM attack using the option 1, or a DNS-spoofing
attack.

The MITM attack uses ARPSPOOF.

The core of this framework is the possibility to perform a DNS attack against every single page, but it will be necessary that
the victim has not visited that webpage in a long time. This is because modern browsers usually saves the IP addresses of the
most recently visited pages, and it will not take our fake IP as the good one. It is also possible to focus the attack in a
single page.

## REQUIREMENTS
Python Scapy

dsniff (sudo apt install dsniff)

netifaces (sudo pip install netifaces)

A local server running on localhost

## USAGE
sudo python interface.py
 hola
