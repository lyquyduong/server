#!/bin/bash

./build.sh nodocker
az webapp deployment source config-zip -g bitwarden-qa -n portal-i4ov5h9 --src Portal.zip
