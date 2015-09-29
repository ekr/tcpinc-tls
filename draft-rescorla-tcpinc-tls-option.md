---
title: TCP Use TLS Option
abbrev: TCP/TLS Opt
docname: draft-rescorla-tcpinc-tls-option-latest
date: 2015
category: std

ipr: trust200902
area: TSV
workgroup: TCPING
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs, rfcedstyle]

author:
 -
       ins: E. Rescorla
       name: Eric Rescorla
       organization: Mozilla
       email: ekr@rtfm.com

normative:
  RFC2119:
  RFC5246:
  RFC5925:
  RFC5705:
  RFC7250:
  I-D.ietf-tls-applayerprotoneg:
  I-D.ietf-tls-session-hash:
  I-D.ietf-tls-tls13:
  I-D.bittau-tcpinc-tcpeno:
  I-D.ietf-tls-chacha20-poly1305:
  I-D.irtf-cfrg-curves:
  
informative:
  RFC5929:
  RFC6919:
  I-D.bittau-tcp-crypt:
  I-D.ietf-tls-falsestart:

--- abstract

This document defines the use of TLS {{RFC5246}} with the TCP-ENO
option {{I-D.bittau-tcpinc-tcpeno}}.


--- middle

# Introduction

RFC EDITOR: PLEASE REMOVE THE FOLLOWING PARAGRAPH The source for this
draft is maintained in GitHub.  Suggested changes should be submitted
as pull requests at https://github.com/ekr/tcpinc-tls.
Instructions are on that page as well.

The TCPINC WG is chartered to define protocols to provide ubiquitous,
transparent security for TCP connections. The WG has specified 
The TCP Encryption Negotiation Option (TCP-ENO) {{I-D.bittau-tcpinc-tcpeno}}
which allows for negotiation of encryption at the TCP layer. This
document describes a binding of TLS {{RFC5246}} to TCP-ENO as
what ENO calls an "encryption spec", thus allowing TCP-ENO
to negotiate TLS.

# Overview

The basic idea behind this draft is simple. The SYN and SYN/ACK
messages carry the TCP-ENO options indicating the willingness to do TLS.
If both sides want to do TLS, then a TLS handshake is started and once
that completes, the data is TLS protected prior to being sent over TCP.
Otherwise, the application data is sent as usual.

             Client                                    Server
      
             SYN + TCP-ENO [TLS]->
                                   <- SYN/ACK + TCP-ENO [ENO]
             ACK ->
             <---------------- TLS Handshake --------------->
             <--------- Application Data over TLS ---------->
             
                  Figure 1: Negotiating TLS with TCP-TLS
      
      
             Client                                    Server
      
             SYN + TCP-ENO [TLS] ->
                                                   <- SYN/ACK
             ACK ->
             <--------- Application Data over TLS ---------->
             
                       Figure 2: Fall back to TCP

If use of TLS is negotiated, the data sent over TCP simply is
TLS data in compliance with {{RFC5246}}.



# TLS Profile

The TLS Profile defined in this document is intended to be a
compromise between two separate use cases. For the straight TCPINC use
case of ubiquitous transport encryption, we desire that
implementations solely implement TLS 1.3 {{I-D.ietf-tls-tls13}} or
greater. However, we also want to allow the use of TCP-ENO as a signal
for applications to do out-of-band negotiation of TLS, and those
applications are likely to already have support for TLS 1.2
{{RFC5246}}. In order to accomodate both cases, we specify a wire
encoding that allows for negotiation of multiple TLS versions
{{extension-definition}} but encourage implementations to
implement only TLS 1.3. Implementations which also implement TLS 1.2
MUST implement the profile described in {{tls12-profile}}


## TLS 1.3 Profile {#tls13-profile}

TLS 1.3 is the preferred version of TLS for this specification. In
order to facilitate implementation, this section provides a
non-normative description of the parts of TLS 1.3 which are relevant
to TCPINC. {{I-D.ietf-tls-tls13}} remains the normative reference for
TLS 1.3 and bracketed references (e.g., [S. 1.2.3.4] refer to the
corresponding section in that document.)
In order to match TLS terminology, we use the term "client"
to indicate the TCP-ENO "A" role (See {{I-D.bittau-tcpinc-tcpeno}};
Section 3.1) and "server" to indicate the "B" role.

### Handshake Modes

TLS 1.3 as used in TCPINC supports two handshake modes, both based
on (EC)DHE key exchange.

* A 1-RTT mode which is used when the client has no information
  about the server's keying material (see {{tls-full}})

* A 0-RTT mode which is used when the client and server have
  connected previous and which allows the client to send data
  on the first flight (see {{tls-0-rtt}}

Full TLS 1.3 includes support for additional modes based on pre-shared
keys, but TCPINC implementations MAY opt to omit them. Implementations
MUST implement the 1-RTT mode and SHOULD implement the 0-RTT mode.


~~~
     Client                                               Server

     ClientHello
       + ClientKeyShare        -------->
                                                     ServerHello
                                                 ServerKeyShare*
                                           {EncryptedExtensions}
                                          {ServerConfiguration*}
                                                  {Certificate*}
                                            {CertificateVerify*}
                               <--------              {Finished}
     {Finished}                -------->
     [Application Data]        <------->      [Application Data]

            *  Indicates optional or situation-dependent
               messages that are not always sent.

            {} Indicates messages protected using keys
               derived from the ephemeral secret.

            [] Indicates messages protected using keys
               derived from the master secret.
~~~
{: #tls-full title="Message flow for full TLS Handshake"}

Note: Although these diagrams indicate a message called
"Certificate", this message MAY either contain a bare public key
or an X.509 certificate (this is intended to support the
out-of-band use case indicated above). Implementations
MUST support bare public keys and MAY support X.509
certificates.

~~~
       Client                                               Server

       ClientHello
         + ClientKeyShare
         + EarlyDataIndication
       (EncryptedExtensions)
       (Application Data)        -------->
                                                       ServerHello
                                             + EarlyDataIndication
                                                    ServerKeyShare
                                             {EncryptedExtensions}
                                            {ServerConfiguration*}
                                                    {Certificate*}
                                             {CertificateRequest*}
                                              {CertificateVerify*}
                                 <--------              {Finished}
       {Finished}                -------->

       [Application Data]        <------->      [Application Data]

            () Indicates messages protected using keys
               derived from the static secret.
~~~
{: #tls-0-rtt title="Message flow for a zero round trip handshake"}



### Basic Handshake

In order to initiate the TLS handshake, the client sends a "ClientHello"
message [S. 6.3.1.1].

~~~~
       struct {
           ProtocolVersion client_version = { 3, 4 };    /* TLS v1.3 */
           Random random;
           uint8 session_id_len_RESERVED;                /* Must be zero */
           CipherSuite cipher_suites<2..2^16-2>;
           uint8 compression_methods_len_RESERVED;       /* Must be zero */
           Extension extensions<0..2^16-1>;
       } ClientHello;
~~~~

The fields listed here have the following meanings:

{:br: vspace="0"}

client_version
: The version of the TLS protocol by which the client wishes to
  communicate during this session.

random
: A 32-byte random nonce.

cipher_suites
: This is a list of the cryptographic options supported by the
  client, with the client's first preference first.
{: br}

extensions contains a set of extension fields. The client MUST include the
following extensions:

SignatureAlgorithms [S. 6.3.2.1]
: A list of signature/hash algorithm pairs the client supports

NamedGroup [S. 6.3.2.2]
: A list of (EC)DHE groups that the client supports

ClientKeyShare [S. 6.3.2.3]
: Zero or more (EC)DHE shares drawn from the groups in NamedGroup.
This SHOULD contain either a P-256 key or an X25519 key.
{: br}


The client SHOULD also include a ServerCertTypeExtension containing
type "Raw Public Key" {{RFC7250}}, indicating its willingness to
accept a raw public key rather than an X.509 certificate in the
server's Certificate message.



  

## TLS 1.2 Profile {#tls12-profile}

Implementations MUST implement and require the TLS Extended Master
Secret Extension {{I-D.ietf-tls-session-hash}} and MUST NOT negotiate
versions of TLS prior to TLS 1.2. Implementations MUST NOT negotiate
non-AEAD cipher suites and MUST use only PFS cipher suites with a key
of at least 2048 bits (finite field) or 256 bites (elliptic curve).


## Cryptographic Algorithms 

Implementations of this specification MUST implement the following cipher
suites:

~~~~
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 
~~~~

These cipher suites MUST support both digital signatures and key exchange
with secp256r1 (NIST P-256) and SHOULD support key agrement with X25519
{{I-D.irtf-cfrg-curves}}.

Implementations of this specification SHOULD implement the following cipher suites:

~~~~
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
~~~~







# Extension Definition

[TODO: How to jointly support TLS 1.2 and TLS 1.3]

                          






If an endpoint sends the TCP-TLS option and correctly
receives it from the other side it SHALL immediately negotiate TLS, taking on the role
described above. Figure 3 shows a detailed message flow for TLS 1.2
using an anonymous cipher suite such as DH_anon (this is the simplest
practice for the case where no authentication is desired or where
a channel binding {{channel-bindings}} is to be used). The point
at which each side is able to write is marked with @@@ (assuming
False Start {{I-D.ietf-tls-falsestart}}).

~~~
             SYN + TCP-TLS ->
                                         <- SYN/ACK + TCP/TLS
             ACK ->
             ClientHello ->
                                                  ServerHello
                                           ServerKeyExchange*
                                              ServerHelloDone
             ClientKeyExchange
             [ChangeCipherSpec]
             Finished            ->
             @@@
   
                                           [ChangeCipherSpec]
                                                  <- Finished
                                                          @@@

             <--------- Application Data over TLS ---------->
             
                Figure 3: Complete protocol flow for TLS 1.2
~~~


Figure 4 shows the same scenario for TLS 1.3 
{{I-D.ietf-tls-tls13}} in the "1-RTT mode"
which is the basic mode for two endpoints which have never
communicated before:

~~~
             SYN + TCP-TLS ->
                                         <- SYN/ACK + TCP/TLS
             ACK ->
             ClientHello + ClientKeyShare ->
                                                  ServerHello
                                              ServerKeyShare*
                                                     Finished
                                                          @@@
             Finished            ->
             @@@
  
             <--------- Application Data over TLS ---------->
             
                Figure 4: Complete protocol flow for TLS 1.2
~~~

Note that in future communications, the client can start sending
data on its first flight (0-RTT mode) if the server provides
a ServerConfiguration.

Once the TLS handshake has completed, all application data SHALL be
sent over that negotiated TLS channel. Application data MUST NOT
be sent prior to the TLS handshake.

If the TLS handshake fails for non-cryptographic reasons such as
failure to negotiate a compatible cipher or the like, endpoints SHOULD
behave as if the the TCP-TLS option was not present. This is obviously
not the conventional behavior for TLS failure, but as the entire idea
here is to be opportunistic and the attacker can simply suppress the
TCP-TLS option entirely, this provides the maximum robustness against
broken intermediaries. If the TLS handshake fails for cryptographic
reasons that indicate damage to the datastream (e.g., a decryption
failure or a Finished failure) then the endpoints SHOULD signal a
connection failure, as this suggests that there is a middlebox
modifying the data and there is a reasonable chance that the state is
now corrupted.


# Transport Integrity

The basic operational mode defined by TCP-TLS protects only the
application layer content, but not the TCP segment metadata.
Upon receiving a packet, implementations MUST first check the
TCP checksum and discard corrupt packets without presenting
them to TLS. If the TCP checksum passes but TLS integrity
fails, the connection MUST be torn down.

Thus, TCP-TLS provides automatic security for the content, but not
protection against DoS-style attacks.  For instance, attackers will be
able to inject RST packets, bogus application segments, etc.,
regardless of whether TLS authentication is used.  Because the
application data is TLS protected, this will not result in the
application receiving bogus data, but it will constitute a DoS on the
connection.

This attack can be countered by using TCP-TLS in combination
with TCP-AO {{RFC5925}}, as follows:

1. The TLS connection is negotiated using the "tcpao"
   ALPN {{I-D.ietf-tls-applayerprotoneg}} indicator.

1. Upon TLS handshake completion,
   a TLS Exporter {{RFC5705}} is used to generate keying
   material of appropriate length using exporter label TBD.

1. Further packets are protected using TCP-AO with the generated
   keys.

The Finished messages MUST NOT be protected with AO. The first
application data afterwards MUST be protected with AO. Note that
because of retransmission, non-AO packets may be received after
AO has been engaged; they MUST be ignored.

[[OPEN ISSUE: How do we negotiate the parameters? Do we
need a use_ao option like with RFC 5764? Is ALPN really
what we want here?]]

[[TODO: verify that the state machine matches up here.]]


# Implementation Options

There are two primary implementation options for TCP-TLS:

* Implement all of TCP-TLS in the operating system kernel.

* Implement just the TCP-TLS negotiation option in the
  operating system kernel with an interface to tell the
  application that TCP-TLS has been negotiated and therefore
  that the application must negotiate TLS.

The former option obviously achieves easier deployment for
applications, which don't have to do anything, but is more
effort for kernel developers and requires a wider interface
to the kernel to configure the TLS stack. The latter option
is inherently more flexible but does not provide as immediate
transparent deployment. It is also possible for systems to
offer both options.

# TLS Profile

Implementations of this specification MUST at minimum support TLS 1.2
{{RFC5246}} and MUST support the following cipher suites [TBD]
and MUST NOT negotiate versions of TLS prior to TLS 1.2. Implementations MUST
NOT negotiate non-AEAD cipher suites and MUST use only PFS cipher
suites with a key of at least 2048 bits (finite field) or 256 bites
(elliptic curve). Implementations MUST implement and require the TLS
Extended Master Secret Extension {{I-D.ietf-tls-session-hash}}.

[[OPEN ISSUE: What cipher suites? Presumably we require one
authenticated and one anonymous cipher suite, all with GCM.]]
[[OPEN ISSUE: If TLS 1.3 is ready, we may want to require that.]]


# Channel Bindings

This specification is compatible with external authentication via
TLS Channel Bindings {{RFC5929}}. 


# NAT/Firewall considerations

If use of TLS is negotiated, the data sent over TCP simply is TLS data
in compliance with {{RFC5246}.  Thus it is extremely likely to pass
through NATs, firewalls, etc. The only kind of middlebox that is
likely to cause a problem is one which does protocol enforcement that
blocks TLS on arbitrary (non-443) ports but *also* passes unknown TCP
options. Although no doubt such devices do exist, because this is a
common scenario, a client machine should be able to probe to determine
if it is behind such a device relatively readily.

# IANA Considerations

IANA [shall register/has registered] the TCP option XX for TCP-TLS.

IANA [shall register/has registered] the ALPN code point "tcpao"
to indicate the use of TCP-TLS with TCP-AO.


# Security Considerations

The mechanisms in this document are inherently vulnerable to active
attack because an attacker can remove the TCP-TLS option, thus
downgrading you to ordinary TCP. Even when TCP-AO is used, all that is
being provided is continuity of authentication from the initial
handshake. If some sort of external authentication mechanism was
provided or certificates are used, then you might get some protection
against active attack.

Once the TCP-TLS option has been negotiated, then the connection is
resistant to active data injection attacks. If TCP-AO is not used,
then injected packets appear as bogus data at the TLS layer and
will result in MAC errors followed by a fatal alert. The result
is that while data integrity is provided, the connection is not
resistant to DoS attacks intended to terminate it.

If TCP-AO is used, then any bogus packets injected by an attacker
will be rejected by the TCP-AO integrity check and therefore will
never reach the TLS layer. Thus, in this case, the connection is
also resistant to DoS attacks, provided that endpoints require
integrity protection for RST packets. If endpoints accept
unauthenticated RST, then no DoS protection is provided.


--- back
