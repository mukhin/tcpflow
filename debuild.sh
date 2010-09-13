#!/bin/bash

if [[ ! -e build-release ]]; then
  touch build-release
  make
fi
