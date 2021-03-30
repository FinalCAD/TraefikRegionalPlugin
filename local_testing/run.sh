#!/bin/bash
cd .. && go mod vendor && cd local_testing && docker-compose up && rm -fr ../vendor/