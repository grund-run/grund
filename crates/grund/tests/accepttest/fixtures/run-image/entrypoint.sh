#!/bin/sh
set -eu
case "${1:-}" in
  serve)
    trap 'exit 0' TERM INT
    while :; do sleep 1; done
    ;;
  exit23|hold)
    mode=$1
    marker=$2
    test "$#" -eq 7
    test "$4" = 'two words'
    test "$5" = ''
    test "$6" = '*'
    test "$7" = '$(touch /must-not-exist)'
    test ! -e /must-not-exist
    printf 'grund-run-stdout:%s\n' "$marker"
    printf 'grund-run-stderr:%s\n' "$marker" >&2
    if [ "$mode" = exit23 ]; then exit 23; fi
    trap 'exit 0' TERM INT
    while :; do sleep 1; done
    ;;
  *) exit 97 ;;
esac
