.. SPDX-License-Identifier: GPL-2.0-or-later
..
.. February 25 2023, Christian Hopps <chopps@labn.net>
..
.. Copyright (c) 2023, LabN Consulting, L.L.C.
..
..

*****
MGMTD
*****



MGMTD Overview
==============

Here's an overview of ``mgmtd``

Here's a sequence diagram

.. seqdiag::

   // attributes that unfortunately don't work in seqdiag:
   //  default_group_color = lightblue;
   // FE-adapter <--  txn-cfg  [label = "success"];
   // front-end     FE-adapter     DB     BE-adapter(staticd)     BE-lib     BE-callbacks
   diagram {
     default_fontsize = 12;
     default_node_color = lightyellow;
     // default_linecolor = red;
     // default_textcolor = blue;
     default_shape = roundedbox;
     span_height = 20;  // default value is 40

     front-end ->  FE-adapter  [label = "COMMIT / CONFIG_REQ", style="dashed", hstyle="generalization"];
                   FE-adapter ->   DB  [label = "create transaction",
                   style="dotted", hstyle = "composition"]
                   FE-adapter ->   DB  [label = "apply config", hstyle="aggregation"];

          DB => BE-callbacks [label = "create txn", return = "success"];
          DB => BE-callbacks [label = "create config", return = "success"];
          DB => BE-callbacks [label = "validate config", return = "success"];
          DB => BE-callbacks [label = "apply config", return = "success"];
          FE-adapter <--  DB  [label = "success"];
     front-end <--  FE-adapter  [label = "success"];

     group {
       color = lightblue;
       fontsize = 24;
       label = "netconf";
       front-end;
     }
     group {
       color = lightblue;
       fontsize = 24;
       label = "mgmtd";
       FE-adapter; DB; BE-adapter;
     }
     group {
       color = lightblue;
       fontsize = 24;
       label = "staticd";
       BE-callbacks;
     }
   }
