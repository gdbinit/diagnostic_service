Diagnostic Service

(c) fG! 2014, 2015

reverser@put.as - https://reverse.put.as


This is an OS X kernel extension/rootkit loader that leverages processor_set_tasks() vulnerability.

It bypasses kernel extensions code signing and regular kernel extensions APIs.

Only tested to load regular kernel extensions, untested with IOKit drivers but should work straightforward or with minimal adaptations.

Can load the kernel extensions from local disk or remote http/https website. Leaves no traces on kextstat or kernel extensions related data structures since kernel extensions APIs are not used.

** REQUIRES ROOT PRIVILEGES **

The code contains Ian Beer's Mavericks exploit for privilege escalation. This means this whole code can work from unprivileged user. 
The exploit still works as of Security Update 2015-001 (untested with 2015-002 but should also work).

Handle with care, you are solely responsible for your acts with this code ;-)

Presented at CodeBlue 2014 and SyScan 2015. Greetings to both :-)

Slides available at https://reverse.put.as, and a few extra tricks when the book is out.

Might contain small traces of bugs and other dangerous stuff. Don't use if allergic to such things!

Have fun,

fG!