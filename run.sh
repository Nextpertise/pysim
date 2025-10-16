#!/bin/bash

docker run -v $(pwd)/csv_files:/files --rm -it --device /dev/bus/usb registry.nextpertise.tools/nextpertise/pysim:latest $@