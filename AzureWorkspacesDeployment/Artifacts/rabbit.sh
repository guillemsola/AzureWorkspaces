#!/bin/bash

apt-get update
apt-get upgrade -y
apt-get install rabbitmq-server -y
rabbitmq-plugins enable rabbitmq_management
rabbitmqctl add_user portal workspace2017!
rabbitmqctl set_user_tags portal administrator
rabbitmqctl set_permissions -p / portal ".*" ".*" ".*"