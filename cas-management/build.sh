#!/bin/bash


function help() {
	echo "Usage: build.sh [copy|clean|package|run]"	
}

function clean() {
    rm -Rf *.log
    rm -Rf *.log.gz
	./mvnw clean "$@"
}

function package() {
	./mvnw clean package -T 5 "$@"
	copy
}


function run() {
	package && java -Xdebug -Xrunjdwp:transport=dt_socket,address=5000,server=y,suspend=n -jar target/cas-management.war 
}

if [ $# -eq 0 ]; then
    echo -e "No commands provided. Defaulting to [run]\n"
    run
    exit 0
fi


case "$1" in
"copy")
    copy 
    ;;
"clean")
	shift
    clean "$@"
    ;;   
"package")
	shift
    package "$@"
    ;;
"run")
    run "$@"
    ;;
*)
    help
    ;;
esac

