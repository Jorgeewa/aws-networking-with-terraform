# AWS - NETWORKING - BASICS
![networking-image](basic%20aws%20networking.drawio.png)

This project implements a basic aws network. It is created with terraform and a microservice architecture. 

There are two private and public subnets sitting in two availability zones with two flask servers and a load balancer managing the traffic between them. Finally there is an sqs message broker sitting between the servers and a python service that sends an email.