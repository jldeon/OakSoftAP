#!/bin/bash
echo
echo Writing Oak update enhancing TCP settings.
echo To restore previous values:
cur=`cat /proc/sys/net/ipv4/tcp_window_scaling`
echo "echo $cur > /proc/sys/net/ipv4/tcp_window_scaling"
cur=`cat /proc/sys/net/ipv4/tcp_timestamps`
echo "echo $cur > /proc/sys/net/ipv4/tcp_timestamps"
cur=`cat /proc/sys/net/ipv4/tcp_retrans_collapse`
echo "echo $cur > /proc/sys/net/ipv4/tcp_retrans_collapse"
cur=`cat /proc/sys/net/ipv4/tcp_orphan_retries`
echo "echo $cur > /proc/sys/net/ipv4/tcp_orphan_retries"
cur=`cat /proc/sys/net/ipv4/tcp_frto`
echo "echo $cur > /proc/sys/net/ipv4/tcp_frto"
cur=`cat /proc/sys/net/ipv4/tcp_retries1`
echo "echo $cur > /proc/sys/net/ipv4/tcp_retries1"


echo 0 > /proc/sys/net/ipv4/tcp_window_scaling
echo 0 > /proc/sys/net/ipv4/tcp_timestamps
echo 0 > /proc/sys/net/ipv4/tcp_retrans_collapse
echo 2 > /proc/sys/net/ipv4/tcp_orphan_retries
echo 1 > /proc/sys/net/ipv4/tcp_frto
echo 6 > /proc/sys/net/ipv4/tcp_retries1