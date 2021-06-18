#!/bin/bash

if [[ "$1" == "--build" ]]; then
    ./build.sh nodocker
fi

az webapp deployment source config-zip -g bitwarden-qa -n portal-i4ov5h9 --src Portal.zip
