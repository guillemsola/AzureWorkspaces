#!/bin/bash
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get upgrade -qy
apt-get install rabbitmq-server -qy
service rabbitmq-server restart
rabbitmq-plugins enable rabbitmq_management
rabbitmqctl add_user portal workspace2017!
rabbitmqctl set_user_tags portal administrator
rabbitmqctl set_permissions -p / portal ".*" ".*" ".*"