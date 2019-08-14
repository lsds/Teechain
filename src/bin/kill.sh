#!/bin/bash

echo "Killing teechain processes"

while [ "$(ps aux | grep teechain | grep ghost | wc -l)" -ne 0 ]; do
    kill -9 $(ps aux | grep teechain | grep ghost | awk '{print $2}')
    sleep 0.1
done

