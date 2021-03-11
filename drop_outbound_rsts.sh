#!/bin/bash

iptables -I OUTPUT -p tcp --tcp-flags ALL RST,ACK -j DROP
iptables -I OUTPUT -p tcp --tcp-flags ALL RST -j DROP
