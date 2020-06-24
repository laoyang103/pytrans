#!/bin/bash

cp ipmstream /usr/local/bin
cp libstdc++.so.6.0.21 /usr/lib/x86_64-linux-gnu/
cd /usr/lib/x86_64-linux-gnu/
ln -sf libstdc++.so.6.0.21 /usr/lib/x86_64-linux-gnu/libstdc++.so.6
ldconfig
