#!/usr/bin/python

from ldtp import *
#import ldtp
import string, sys, os

def own_close_windows():
	print "Close all windows"
	for i in reversed(getwindowlist()):
		for ii in getobjectlist(i):
			if ii == 'btnClose':
				click (i, ii)
				print "Nice close"

		print "close " + i
		if guiexist(i):
			print "Force close"
			closewindow(i)
	sys.exit(1)

def debug():
	print "Found following windows:"
	print getwindowlist()
	print ""

	for i in getwindowlist():
		msg="Window '"+i+"' has following objects:"
		print "#"*len(msg)
		print msg
		print getobjectlist(i)
		print ""


def own_click(win, but):
	not_clicked=1
	for i in getwindowlist():
		if ( i == win ):
			for ii in getobjectlist(i):
				if ( ii == but ):
					click (win, but)
					not_clicked=0
	if not_clicked:
		debug()
		print "No '" + but + "' in '" + win + "'"
		time.sleep(1)
		own_close_windows()
	return not_clicked


def own_settextvalue (win, form, txt):
	not_clicked=1
	for i in getwindowlist():
		if ( i == win ):
			for ii in getobjectlist(i):
				if ( ii == form ):
					settextvalue(win, form, txt)
					not_clicked=0
	if not_clicked:
		debug()
		print "No '" + form + "' in '" + win + "'"
		time.sleep(1)
		own_close_windows()
	return not_clicked


if not os.path.isfile(sys.argv[1]):
	print "No suc file '"+sys.argv[1]+"'"
	sys.exit(1)

def main():
	retval=1
	launchapp (sys.argv[1])

	time.sleep(5)


	print "Select LinuxIGD2"
	try:
		selectrow ('frmGUPnPUniversalControlPoint', 'ttbl0', 'Linux Internet Gateway Device')
	except:
		debug()
	else:
		selectrow ('frmGUPnPUniversalControlPoint', 'ttbl0', 'Linux Internet Gateway Device')
		time.sleep(3)


	print "Select PBC method"
	retval=own_click( 'frmGUPnPUniversalControlPoint', 'mnuStartwpssetupPBCmethod')
	time.sleep(8)
	print "Send USR2 to upnpd"
	os.system("sudo pkill -USR2 upnpd")
	time.sleep(5)

	print "Click OK"
	retval=own_click ('dlgInformation', 'btnClose')
	time.sleep(4)



	for i in getwindowlist():
		if ( i == 'dlgDeviceIntroduction' ):
			print "Try to close extra device introduction window, this is a harmless bug"
			retval=own_click('dlgDeviceIntroduction', 'btnCancel')

	time.sleep(3)


	#Administrator login
	#"Administrator" "admin password"
	print "Select login"
	retval=own_click( 'frmGUPnPUniversalControlPoint', 'mnuUserloginsetup')
	time.sleep(3)


	print "Add username and password"
	retval=own_settextvalue('dlgUserloginsetup', 'txt1', 'Administrator')
	retval=own_settextvalue('dlgUserloginsetup', 'txt0', 'admin password')
	time.sleep(3)

	print "Login"
	retval=own_click('dlgUserloginsetup', 'btnLogin')
	time.sleep(3)

	retval=own_click('dlgInformation', 'btnClose')
	time.sleep(3)

	print "Logout"
	retval=own_click('dlgUserloginsetup', 'btnLogout')
	time.sleep(3)

	retval=own_click('dlgInformation', 'btnClose')
	time.sleep(3)

	print "Close User Login win"
	retval=own_click('dlgUserloginsetup', 'btnClose')

	#debug()

	print "all done"

	time.sleep(3)

	print "Quit"

	for i in getwindowlist():
		if ( i == 'frmGUPnPUniversalControlPoint' ):
			click ('frmGUPnPUniversalControlPoint', 'mnuQuit')


	return retval

if __name__ == "__main__":
	main()
