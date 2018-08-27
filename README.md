# openflow-loadbalancer
SDN OpenFlow load balancer based on Ryu Controller. This load balancing application implements round-robin 
algorithm and uses OpenFlow 1.0.

## Adaption 
The class *Network* in the file *network_setup.py* provides needed configuration of load balancing application,
which includes: (1) server parameters, (2) MAC and IP of load balancer and (3) alternative set of servers in
case of e.g. often change of environment - from mininet to real hardware and vice versa.

Member function *set_default_flows()* of the main class *LoadBalancingApp* allows to install default flows 
upon OpenFlow channel establishment. As an example, we blocked IPv6 traffic, but it can be further extended 
with other rules.

## Usage
The application can simply be run using *ryu-manager*:

```
$ ryu-manager load_balancer.py
```