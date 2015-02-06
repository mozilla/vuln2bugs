vuln2bugs
=========

What is this?
-------------

This is a program that takes vulnerability, asset, service, compliance data out of MozDef and figures out which teams
should run security updates on their systems. MozDef is used as a state database and is fed through various other
programs such as Nexpose and MIG.

Here's a rough diagram of what this looks like:

::

      +---------------------+                                                                                            
      |                     |                                                                                            
      |    MIG (compliance  |                                                                                            
      |    data)            +---------+                                                                                  
      |                     |         |                                                                 +----------+     
      +---------------------+         |                                                                 |          |     
                                    +-+-------------------+              +----------------+             | Bugzilla |     
       +---------+----------+       |                     |              |                |             |          |     
       | Nexpose/vintmgr    |       |                     |              |    vuln2bugs   |             |          |     
       | Vulnerability data +------->    MozDef (JSON/ES) <-------------->                <------------->          |     
       |                    |       |                     |              |                |             |          |     
       |                    |       |                     |              +----------------+             |          |     
       +--------------------+       +--+------------------+                                             +----------+     
                                       |                                                                                 
     +----------------------+          |                                                                                 
     |                      |          |                                                                                 
     |   Asset data         |          |                                                                                 
     |   (Various)          +----------+                                                                                 
     |                      |                                                                                            
     |                      |                                                                                            
     +----------------------+                                                                                            
                                                                                                                       
