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


Usage
-----

When vuln2bugs runs, it will:

1. Check for the current vulnerabilities found per asset and per team (autogroup in MozDef).
2. Check no prior bug exists, if none do, create a new bug to the configured team.
  a. Attach a list of vulnerable hosts (currently 2 attachments: CSV and "detailed")
  b. Indicate the due date and set some whiteboard tags
3. If a bug exits, check if it needs updating.
  a. Update attachments if more or less vulnerabilities have been found since last run.
  b. Remind on the bug if it's paste due date (SLA) and set a NEEDINFO flag.
  c. Close the bug if all vulnerabilities have been fixed.

Vuln2bugs is expected to run after each vmintgr run (see https://github.com/ameihm0912/vmintgr/).

Configuration
-------------

Vuln2bugs uses a HJSON file for configuration. See the example vuln2bugs.json.inc file, it contains a bunch of comments
to help you configure this script.

The per team filters are extremely flexible and any valid MozDef field can be used/selected, including fields that
have not been created at vuln2bug's birth.

You'll need to rename the file to vuln2bugs.json for things to work :)

FAQ
---

Q: How do I make the script shut up?
A: Remove the whiteboard tag "v2b-autoremind".

Q: How do I force the script to leave the bug open?
A: Remove the whiteboard tag "v2b-autoclose".

Q: How to I make the script shut up for a while (i.e. push back the SLA reminder)?
A: Change the whiteboard tag "v2b-duedate=YYYY-MM-DD" to the day you want.
