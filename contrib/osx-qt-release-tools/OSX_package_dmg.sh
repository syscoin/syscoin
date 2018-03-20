#!/bin/bash
#THIS SCRIPT SHOULD BE RUN AS ROOT!!!
echo "============================"
echo "OSX Packager for Syscoin"
echo "============================"

read -p "Run binary packager? (y/n):" binaryPackage
if [ "$binaryPackage" = "y" ]; then
	echo "Running binary packager..."
	read -p "Verbose output? (y/n):" verboseOutput

	#rename port-based db48 dir pre-packaging
	mv /opt/local/lib/db48 /opt/local/lib/lib

	#run macdeploy without the DMG command so we can fix the db48 linker manually
	if [ "$verboseOutput" = "y" ]; then
		echo "VERBOSE OUTPUT"
  		macdeployqt Syscoin-Qt.app/ -verbose=3
	else
		echo "NONVERBOSE OUTPUT"
  		macdeployqt Syscoin-Qt.app/
	fi

	#rename port-based db48 to the right name
	mv /opt/local/lib/lib /opt/local/lib/db48

	#fix linker ids
	install_name_tool -id @executable_path/../Frameworks/libdb_cxx-4.8.dylib "Syscoin-Qt.app/Contents/MacOS/Syscoin-Qt"
	install_name_tool -change /opt/local/lib/db48/libdb_cxx-4.8.dylib @executable_path/../Frameworks/libdb_cxx-4.8.dylib "Syscoin-Qt.app/Contents/MacOS/Syscoin-Qt"
fi

read -p "Attempt to fix BOOST linkages? (y/n):" fixBoost
if [ "$fixBoost" = "y" ]; then
	echo "Attempting to fix boost linkages..."
	echo "Current path:" 
	pwd
	
	#move into the syscoin dir
	cd ./Syscoin-Qt.app/Contents/Frameworks
	
	echo "Boost repair path:" 
	pwd

	install_name_tool -id @executable_path/../Frameworks/libboost_chrono-mt.dylib libboost_chrono-mt.dylib 
	install_name_tool -change /opt/local/lib/libboost_system-mt.dylib @executable_path/../Frameworks/libboost_system-mt.dylib libboost_chrono-mt.dylib 

	install_name_tool -id @executable_path/../Frameworks/libboost_filesystem-mt.dylib libboost_filesystem-mt.dylib 
	install_name_tool -change /opt/local/lib/libboost_system-mt.dylib @executable_path/../Frameworks/libboost_system-mt.dylib libboost_filesystem-mt.dylib 

	install_name_tool -id @executable_path/../Frameworks/libboost_program_options-mt.dylib libboost_program_options-mt.dylib

	install_name_tool -id @executable_path/../Frameworks/libboost_system-mt.dylib libboost_system-mt.dylib

	install_name_tool -id @executable_path/../Frameworks/libboost_thread-mt.dylib libboost_thread-mt.dylib
	install_name_tool -change /opt/local/lib/libboost_system-mt.dylib @executable_path/../Frameworks/libboost_system-mt.dylib libboost_thread-mt.dylib

	cd ../../../
	echo "Back to main path:" 
	pwd
	
fi

read -p "Create DMG? (y/n):" createDMG

#package the final product into a DMG
if [ "$createDMG" == "y" ]; then
	echo "Creating DMG..."
	macdeployqt Syscoin-Qt.app/ -dmg
fi

#end