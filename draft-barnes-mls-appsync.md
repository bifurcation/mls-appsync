---
title: "An Application Interface to Messaging Layer Security"
abbrev: "MLS App API"
category: info

docname: draft-barnes-mls-appsync-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Messaging Layer Security"
keyword:
 - messaging layer security
 - end-to-end encryption
venue:
  group: "Messaging Layer Security"
  type: "Working Group"
  mail: "mls@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/mls/"
  github: "bifurcation/mls-appsync"
  latest: "https://bifurcation.github.io/mls-appsync/draft-barnes-mls-appsync.html"

author:
 -
    fullname: Richard Barnes
    organization: Cisco
    email: rlb@ipv.sx
 -
    fullname: Rohan Mahy
    organization: Rohan Mahy Consulting Services
    email: rohan.ietf@gmail.com

normative:

informative:


--- abstract

The Messaging Layer Security protocol enables a group of participants to
negotiate a common cryptographic state.  While the primary function of MLS is to
establish shared secret state for the group, an MLS group also captures
authentication information for group participants and information on which the
group has confirmed agreement.  This document defines an interface interface by
which multiple uncoordinated application functions may safely reuse the
cryptographic state of an MLS group for application purposes.

--- middle

# Introduction

The Messaging Layer Security protocol (MLS) is designed to be integrated into
applications, in order to provide security services that the application
requires {{!RFC9420}}.  There are two questions to answer when designing such an
integration:

1. How does the application provide the services that MLS requires?
2. How does the application use MLS to get security benefits?

The MLS Architecture describes the requirements for the first of these questions
{{?I-D.mls-architecture}}, namely the structure of the Delivery Service and
Authentication Service that MLS requires.  This document is focused on the
second question.

MLS itself offers some basic functions that applications can use, such as the
secure message encapsulation (PrivateMessage), the MLS exporter, and the epoch
authenticator.  Current MLS applications make use of these mechanisms to acheive
a variety of confidentiality and authentication properties.

As application designers become more familiar with MLS, there is increasing
interest in leveraging otehr cryptographic tools that an MLS group provides:

- HPKE and signature key pairs for each member, where the private key is known
  only to that member, and the public key is authenticated to the other members.

- A pre-shared key mechanism that can allow an application to inject data into
  the MLS key schedule.

- An exporter mechanism that allows applications to derive secrets from the MLS
  key schedule.

There is also interest in exposing an MLS group to multiple loosely-coordinated
components of an application.  To support these use cases, there is a need for a
mechanism that provides application components access to MLS's cryptographic
tools in a way that ensure that different components' usage will not conflict
with each other, or with MLS itself.

This document defines a set of mechanisms that application components can use to
ensure that their use of these facilities is properly domain-separated from MLS
itself, and from other application components that might be using the same MLS
group.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

We make heavy use of the terminology in the MLS specification {{!RFC9420}}.

Application:
: The system that instantiates, manages, and uses an MLS group.  Each MLS group
is used by exactly one application, but an application may maintain multiple
groups.

Application component:
: A subsystem of an application that has access to an MLS group.

# Protocol Overview

The mechansms in this document take MLS mechanisms that are either not
inherently designed to be used by applications, or not inherently designed to be
used by multiple application components, and adds a domain separator that
separates application usage from MLS usage, and application components' usage
from each other:

- Signing operations are tagged so that signatures will only verify in the
  context of a given component.

- Public-key encryption operations are similarly tagged so that encrypted data
  will only decrypt in the context of a given component.

- Pre-shared keys are identified as originating from a specific component, so
  that differnet components' contributions to the MLS key schedule will not
  collide.

- Exported values include an identifier for the component to which they are
  being exported, so that different components will get different exported
  values.

Application components can use these functions to create advanced security
services.  The signing and public-key encryption functions, for example, could
be used to create a simple facility for authenticated one-to-one messaging
within a group.  An application might export different values for encrypting
real-time media with with SFrame {{?RFC9605}}, or for encrypting information
that is not expected to be forward-secret within in epoch (e.g., a room title).

Pre-shared keys are an especially flexible facility.  The PreSharedKeyID
structure used to signal the use of a PSK in a Proposal or Welcome message can
carry arbitary application data (in the `psk_id` field for `external` PSKs).
Since both the PreSharedKeyID and the secret PSK value are incorporated into the
MLS key schedule, PSKs can be used to incorporate application data into the MLS
key schedule, so that the continued functioning of the MLS group confirms that
the entire group agrees on the application data.

For example, suppose an application component wanted to confirm the group's
agreement on an application-level policy document before enforcing the policy.
The application component wishing to update the policy could cause a Commit to
be emitted that includes a PreSharedKey proposal whose PreSharedKeyID contains
the new policy (with a arbitrary application defined PreSharedKey secret,
possibly empty).  When another member successfully processes this commit, the
corresponding application component at that member would see that the PSK
proposal had confirmed agreement the new application policy, and put the policy
into force.

# Application Component Interface


# Security Considerations

# IANA Considerations


# ========= OLD CONTENT BELOW THIS LINE ==========

# Introduction

Messaging Layer Security (MLS) allows a group of clients to authenticate each
other and establish shared secret state {{!RFC9420}}.  One of the primary
security benefits of MLS is that the MLS key schedule confirms that the group
agrees on certain metadata, such as the membership of the group. Members that
disagree on the relevant metadata will arrive at different keys and be unable to
communicate. Applications based on MLS can integrate their state into this
metadata in order to confirm that the members of an MLS group agree on
application state as well as MLS metadata.

Here, we define two extensions to MLS to facilitate this application design:

1. A GroupContext extension `application_states` that confirms agreement on
   application state from potentially multiple sources.
2. A new proposal type AppSync that allows MLS group members to propose changes
   to the agreed application state.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Application State Synchronization

This document defines a new AppSync proposal. AppSync is a Safe Extension as
defined in {{Section 2 of !I-D.ietf-mls-extensions}}, of type
`extension_external_proposal`.

The `application_states` extension allows the application to inject state
objects into the MLS key schedule. Changes to this state can be made out of
band, or using the AppSync proposal. Using the AppSync proposal ensures that
members of the MLS group have received the relevant state changes before they
are reflected in the group's `application_states`.

> **NOTE:** This design exposes the high-level structure of the application state
> to MLS.  An alternative design would be to have the application state be opaque
> to MLS.  There is a trade-off between generality and the complexity of the API
> between the MLS implementation and the application.  An opaque design would give
> the application more freedom, but require the MLS stack to call out to the
> application to get the updated state as part of Commit processing.  This design
> allows the updates to happen within the MLS stack, so that no callback is
> needed, at the cost of forcing the application state to fit a certain structure.
> It also potentially can result in smaller state updates in large groups.

The state for Each `applicationId` in the `application_states` needs to conform
to one of four basic types: an ordered array, an unordered array, a map, or an
irreducible blob. This allows the AppSync proposal to efficiently modify a large
application state object.

The content of the `application_states` extension and the `AppSync` proposal are
structured as follows:

~~~ tls
enum {
    irreducible(0),
    map(1),
    unorderedList(2),
    orderedArray(3),
    (255)
} StateType;

struct {
  opaque element<V>;
} OpaqueElement;

struct {
  opaque elementName<V>;
  opaque elementValue<V>;
} OpaqueMapElement;

struct {
  uint32 applicationId;
  StateType stateType;
  select (stateType) {
    case irreducible:
      OpaqueElement state;
    case map:
      OpaqueMapElement mapEntries<V>;
    case unorderedList:
      OpaqueElement unorderedEntries<V>;
    case orderedArray:
      OpaqueElement orderedEntries<V>;
  };
} ApplicationState;

struct {
  ApplicationState applicationStates<V>;
} ApplicationStatesExtension;
~~~
{: #fig-app-state title="The `application_state` extension" }

~~~ tls
struct {
  uint32 index;
  opaque element<V>;
} ElementWithIndex;


struct {
  uint32 applicationId;
  StateType stateType;
  select (stateType) {
    case irreducible:
      OpaqueElement newState;
    case map:
      OpaqueElement removedKeys<V>;
      OpaqueMapElement newOrUpdatedElements<V>;
    case unorderedList:
      uint32 removedIndices<V>;
      OpaqueElement addedEntries<V>;
    case orderedArray:
      ElementWithIndex replacedElements<V>;
      uint32 removedIndices<V>;
      ElementWithIndex insertedElements<V>;
      OpaqueElement appenededEntries<V>;
  };
} AppSync;
~~~
{: #fig-app-sync title="The AppSync proposal type" }

The `applicationId` determines the structure and interpretation of the contents.
of an ApplicationState object. AppSync proposals
contain changes to this state, which the client uses to update the
representation of the state in `application_states`.

A client receiving an AppSync proposal applies it in the following way:

* Identify an `application_states` GroupContext extension which contains the
  same `application_id` state as the AppSync proposal
* Apply the relevant operations (replace, remove, update, append, insert)
  according to the `stateType` to the relevant parts of the ApplicationState
  object in `application_states` extension.

An AppSync for an irreducible state replaces its `state` element with a new
(possibly empty) `newState`. An AppSync for a map-based ApplicationState first
removes all the keys in `removedKeys` and than replaces or adds the elements in
`newOrUpdatedElements`. An AppSync for an unorderedList ApplicationState first
removes all the indexes in `removedIndices`, then adds the elements in
`addedEntries`. Finally an AppSync for an orderedArray, replaces all the
elements (index-by-index) in `replacedElements`, the removes the elements in
`removedIndices` according to the then order of the array, then inserts all the
elements in `insertedElements` according to the then order of the array, then
finally appends the `appendedEntries` (in order). All indices are zero-based.

Note that the `application_states` extension is updated directly by AppSync
proposals; a GroupContextExtensions proposal is not necessary. A proposal list
that contains both an AppSync proposal and a GroupContextExtensions proposal
is invalid.

Likewise a proposal list in a Commit MAY contain more than one AppSync proposal,
but no more than one AppSync proposal per `applicationId`. The proposals are
applied in the order that they are sent in the Commit.

AppSync proposals do not need to contain an UpdatePath. An AppSync proposal can
be sent by an authorized external sender.

# Security Considerations

The mechanism defined in this document provides strong authenticity, integrity,
and change control properties to the application state information it manages.
Nobody outside the group can make changes to the application state, and the
identity of the group member making each change is authenticated.

The application data synchronized via this mechanism may or may not be
confidential to the group, depending on whether the AppSync proposal is sent as
an MLS PublicMessage or PrivateMessage.  As with application data, applications
should generally prefer the use of Private Message.  There may be cases,
however, where it is useful for intermediaries to inspect application state
updates, e.g., to enforce policy.

# IANA Considerations

> **TODO:** Register new extension and proposal types.

> **TODO:** IANA registry for `application_id`; register extension and proposal types
>as safe extensions

--- back

# Acknowledgments
{:numbered="false"}

> **TODO:** Acknowledgements.
