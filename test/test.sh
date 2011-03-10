#!/bin/sh

echo ======== Basic ========
./test 'http://root:toor@192.168.1.190/axis-cgi/admin/param.cgi?action=list&group=Properties.Image'

echo ======== Digest ========
./test 'http://admin:4321@192.168.1.100/cgi-bin/about.cgi?msubmenu=about&action=view2'
