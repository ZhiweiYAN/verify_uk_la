#!/bin/sh

kill -9 $(ps -ef|grep run_gdlian|gawk '$0 !~/grep/ {print $2}' |tr -s '\n' ' ')

