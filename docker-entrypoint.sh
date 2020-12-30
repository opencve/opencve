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
    exec opencve init $@
  ;;

  'upgrade-db')
    shift
    exec opencve upgrade-db $@
  ;;

  'import-data')
    shift
    exec opencve import-data $@
  ;;

  'worker')
    shift
    exec opencve celery worker -l INFO $@
  ;;

  'beat')
    shift
    exec opencve celery beat -l INFO $@
  ;;

  'create-user')
    shift
    # john john.doe@example.com P4ssw0rd --admin
    exec opencve create-user $@
  ;;

  'webserver')
    shift
    # john john.doe@example.com P4ssw0rd --admin
    exec opencve webserver $@
  ;;

  *)
    opencve init
    opencve upgrade-db
    yes | opencve import-data 
  	exec opencve webserver $@
	;;
esac
