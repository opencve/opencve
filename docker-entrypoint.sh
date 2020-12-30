#!/bin/sh

set -x
set -e

isArgPassed() {
  arg="$1"
  argWithEqualSign="$1="
  shift
  while [ $# -gt 0 ]; do
    passedArg="$1"
    shift
    case $passedArg in
    $arg)
      return 0
      ;;
    $argWithEqualSign*)
      return 0
      ;;
    esac
  done
  return 1
}

case "$1" in

  'init')
    shift
    su opencve
    exec opencve init $@
  ;;

  'upgrade-db')
    shift
    su opencve
    exec opencve upgrade-db $@
  ;;

  'import-data')
    shift
    su opencve
    exec opencve import-data $@
  ;;

  'worker')
    shift
    su opencve
    exec opencve celery worker -l INFO $@
  ;;

  'beat')
    shift
    su opencve
    exec opencve celery beat -l INFO $@
  ;;

  'create-user')
    shift
    su opencve
    # john john.doe@example.com P4ssw0rd --admin
    exec opencve create-user $@
  ;;

  'webserver')
    shift
    su opencve
    # john john.doe@example.com P4ssw0rd --admin
    exec opencve webserver $@
  ;;

  'bash')
  	ARGS=""
  	shift
    apk add --update --no-cache nano bash jq
	  su opencve
  	exec /bin/bash $@
	;;

  *)
    su opencve
    opencve init
    opencve upgrade-db
    opencve import-data 
  	exec opencve webserver $@
	;;
esac
