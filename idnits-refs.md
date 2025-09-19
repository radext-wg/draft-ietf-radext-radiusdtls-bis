# IDNits Explanation

Downref: Normative to Informational 2866:

> RADIUS Accounting. referenced as normative e.g. by RFC4372 (Chargeable User Identity CUI)

Downref: Normative to Informational RFC3579:

> RADIUS support for EAP.

Obsolete Normative to RFC 5077:

> Session Resumption without Server-side state, obsoleted by 8446 (TLSv1.3)  
  Since we mandate use of TLSv1.2, we need to reference it here.

Downref: Normative to Informational RFC 5176:

> Dynamic authorization extensions. Changes to Packet format are mentioned.

Obsolete Normative to RFC 5246:

> TLSv1.2. Since we mandate use of TLSv1.2, we need to reference it here.

Downref: Normative to Informational RFC 5997:

> Use of Status-Server Packet in RADIUS.  
  Since we mandate use of Status-Server, we need to reference it here.

Obsolete Normative to RFC 6347:

> DTLSv1.2, obsoleted by 9147 (DTLSv1.3)  
  Since we mandate use of DTLSv1.2, we need to reference it here.

Downref Normative to Experimental RFC 7585:

> Dynamic RADIUS Routing.  
  Maybe worth thinking of a 7585bis document, but the referenced parts are well-proven.

Downref Normative to Experimental RFC 7930:

> Larger Packets for RADIUS over TCP, defines the Protocol-Error packet type.  
  Since we use Protocol-Error to signal single-hop failures, we need to reference it here.
