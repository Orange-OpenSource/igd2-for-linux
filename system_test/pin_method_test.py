#!/usr/bin/python

from ldtp import *
#import ldtp
import string, sys, os


if not os.path.isfile(sys.argv[1]):
	print "No suc file '"+sys.argv[1]+"'"
	sys.exit(1)

launchapp (sys.argv[1])
#'/home/kari/tmp_dp/data/bin/gupnp-universal-cp')
time.sleep(5)

data=getobjectlist('frmGUPnPUniversalControlPoint')

print data

time.sleep(5)

print "Select LinuxIGD2"
selectrow ('frmGUPnPUniversalControlPoint', 'ttbl0', 'Linux Internet Gateway Device')
time.sleep(3)
print "Select PIN method"
click( 'frmGUPnPUniversalControlPoint', 'mnuStartwpssetupPINmethod')

time.sleep(5)

print "Add pin"
settextvalue('dlgDeviceIntroduction', 'txt0', '49226874')
time.sleep(2)

print "Click invoke"
click('dlgDeviceIntroduction', 'btnInvoke')
time.sleep(4)

print "Click OK"
wins=getwindowlist()
for i in wins:
	if ( i == 'dlgInformation' ):
		click ('dlgInformation', 'btnOK')

time.sleep(4)

wins=getwindowlist()
for i in wins:
	if ( i == 'dlgDeviceIntroduction' ):
		print "Close extra device introduction window, this is a harmless bug"
		closewindow ('dlgDeviceIntroduction')
print "all done"

time.sleep(3)

print "Quit"

wins=getwindowlist()
for i in wins:
	if ( i == 'frmGUPnPUniversalControlPoint' ):
		click ('frmGUPnPUniversalControlPoint', 'mnuQuit')


#Hope gupnp-univeral-cp  is already closed
sys.exit(1)
