#!/bin/bash

main="`dirname $0`"

ant -f "$main/build/build.xml" build
