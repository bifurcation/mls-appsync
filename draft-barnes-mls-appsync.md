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

Component ID:
: An identifier for an application component.  These identifiers are assigned by
the application.

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

We also define two new general mechanisms that allow applications to take
advantage of the extensibility mechanisms of MLS:

- An `application_data` extension type that associates application data with MLS
  messages, or with the state of the group.

- An ApplicationData proposal type that enables arbitrary application data to
  be associated to a Commit.

- An ApplicationDataUpdate proposal type that enables efficient updates to
  an `application_data` GroupContext extension.

As with the above, information carried in these proposals and extension marked
as belonging to a specific application component, so that components can manage
their information independently.

The separation between components is acheived by the application assigning each
component a unique component ID number.  These numbers are then incorporated
into the appopriate calculations in the protocol to achieve the required
separation.

> TODO: Examples of how an application would use these things

# Application Component Interface

## Component IDs

A component ID is a four-byte value that uniquely identifies a component within
the scope of an application.

```
uint32 ComponentID;
```

> TODO: What are the uniqueness requirements on these?  It seems like the more
> diversity, the better.  For example, if a ComponentID is reused across
> applications (e.g., via an IANA registry), then there will be a risk of replay
> across applications.  Maybe we should include a binder to the group/epoch as
> well, something derived from the key schedule.

> TODO: It might be better to frame these in terms of "data types" instead of
> components, to avoid presuming software architecture.

## Hybrid Public Key Encryption (HPKE) Keys

## Signature Keys

## Pre-Shared Keys

## Exported Secrets

## Carrying Application Data in MLS

MLS provides a few extension points, including `extensions` fields on several
objects and extensible set of proposal types.  This section defines simple,
standard ways for applications to use these extension points.  The intent is to
allow MLS stacks to offer one set of APIs that can serve many application needs,
so that applications don't need to define and negotiate extensions at the MLS
level.

### `application_data` Extension

The MLS GroupContext, LeafNode, KeyPackage, and GroupInfo objects each have an
`extensions` field that can carry additional data not defined by the MLS
specification.  The `application_data` extension provides a generic container
that applications can use to attach application data to these messages.  Each
usage of the extension serves a slightly different purpose:

* GroupContext: Confirms that all members of the group agree on the application
  data, and automatically distributes it to new joiners.

* KeyPackage and LeafNode: Associates the application data to a particular
  client, and advertises it to the other members of the group.

* GroupInfo: Distributes the application data confidentially to the new joiners
  for whom the GroupInfo is encrypted (as a Welcome message).

The content of the `application_data` extension is a serialized
ApplicationDataDictionary object:

~~~ tls-presentation
struct {
    ComponentID component_id;
    opaque data<V>;
} ComponentData;

struct {
    ComponentData component_data<V>;
} ApplicationDataDictionary;
~~~

The entries in the `component_data` MUST be sorted by `component_id`, and there
MUST be at most one entry for each `component_id`.

An `application_data` extension in a LeafNode, KeyPackage, or GroupInfo can be
set when the object is created.  An `application_data` extension in the
GroupContext needs to be manage using the tools available to update GroupContext
extensions: The creator of the group can set extensions unilaterally, and
thereafter, the GroupContextExtensions proposal can be used to update
extensions.  The ApplicationDataUpdate proposal described in
{{applicationdataupdate}} provides a more efficient way to update the
`application_data` extension.

### ApplicationData

The ApplicationData proposal type allows an application component to associate
application data to a Commit, so that the member processing the Commit knows
that all other group members will be processing the same data.  ApplicationData
proposals are ephemeral in the sense that they do not change any persistent
state related to MLS, aside from their appearance in the transcript hash.

The content of an ApplicationData proposal is the same as an `application_data`
extension.  The proposal type is set in {{iana-considerations}}.

~~~ tls-presentation
struct {
    ComponentID component_id;
    opaque data<V>;
} ApplicationData;
~~~

An ApplicationData proposal is invalid if it contains a `component_id` that is
unknown to the application, or if the `application_data` field contains any
`ComponentData` entry whose `data` field is considered invalid by the
application logic registered to the indicated `component_id`.

ApplicationData proposals MUST be processed after any default proposals (i.e.,
those defined in {{RFC9420}}), but before any ApplicationDataUpdate proposals.

A client applies an ApplicationData proposal by providing the contents of the
`application_data` field to the component identified by the `component_id`.  If
a Commit references more than one ApplicationData proposal for the same
`component_id` value, then they MUST be processed in the order in which they are
specified in the Commit.

### ApplicationDataUpdate

Updating the `application_data` with a GroupContextExtensions proposal is
cumbersome.  The application data needs to be transmitted in its entirety, along
with any other extensions, whether or not they are being changed.  And a
GroupContextExtensions proposal always requires an UpdatePath, which updating
application state never should.

The ApplicationDataUpdate proposal allows the `application_data` extension to
be updated without these costs.  Instead of sending the whole value of the
extension, it sends only an update, which is interpreted by the application to
provide the new content for the `application_data` extension.  No other
extensions are sent or updated, and no UpdatePath is required.

```
enum {
    invalid(0),
    update(1),
    remove(2),
    (255)
} ApplicationDataUpdateOperation;

struct {
    ComponentID component_id;
    ApplicationDataUpdateOperation op;

    select (ApplicationDataUpdate.op) {
        case update: opaque update<V>;
        case remove: struct{}
    }
} ApplicationDataUpdate;
```

An ApplicationDataUpdate proposal is invalid if its `component_id` references a
component that is not known to the application, or if it specifies the removal
of state for a `component_id` that has no state present.  A proposal list is
invalid if it includes multiple ApplicationDataUpdate proposals that `remove`
state for the same `component_id`, or proposals that both `update` and `remove`
state for the same `component_id`.  In other words, for a given `component_id`,
a proposal list is valid only if it contains (a) a single `remove` operation or
(b) one or more `update` operation.

> TODO: Deconflict with GroupContextExtensions.

ApplicationDataUpdate proposals are processed after any default proposals (i.e., those
defined in {{RFC9420}}), and any ApplicationData proposals.

A client applies an ApplicationDataUpdate proposal by changing the contents of
the `application_state` extension associated to its local copy of the
GroupContext for the group.

* If the `op` field is set to `set`:

    * If no `application_data` extension is present in the GroupContext, add one
      to the end of the `extensions` list in the GroupContext.

    * Provide the content of the `update` field to the application logic
      registered to the `component_id` value.

    * The application logic returns either an opaque value `new_data` that will be
      stored as the new application data for this component, or else an
      indication that it considers this update invalid.

    * If the application logic considers the update invalid, the MLS client MUST
      consider the proposal invalid.

    * If there is an entry in the `component_data` vector in the
      `application_data` extension with the specified `component_id`, then set
      its `data` field to the specified `new_data`.

    * Otherwise, insert a new entry in the `component_states` vector with the
      specified `component_id` and the `data` field set to the `new_data`
      value.  The new entry is inserted at the proper point to keep the
      `component_states` vector sorted by `component_id`.

* If the `op` field is set to `remove`:

    * If there is an entry in the `component_states` vector in the
      `application_state` extension with the specified `component_id`, remove
      it.

    * Otherwise, the proposal is invalid.

> TODO: An alternative design here would be to have the `update` operation
> simply set the new value for the `application_data` GCE, instead of sending a
> diff.  This would be simpler in that the MLS stack wouldn't have to ask the
> application for the new state value, and would discourage applications from
> storing large state in the GroupContext directly (which bloats Welcome
> messages).  It would effectively require the state in the GroupContext to be a
> hash of the real state.  This pushes some complexity onto the application,
> since the application has to define a hashing algorithm, and could make
> debugging more complex.

# Security Considerations

The API defined in this document provides the following security guarantee: If
an application uses MLS and all its components use this API, then the security
guarantees of the base MLS protocol and the security guarantees of the
components, each analyzed in isolation, still hold for the composed protocol. In
other words, the API protects applications from careless
component developers. As long as all the components use this API, it is not
possible that some combination of components  (the developers of which did not know
about each other) impedes the security of the base MLS protocol or any used
component. No further analysis of the combination is necessary. This also means
that any security vulnerabilities introduced by one component do not spread to
other component or the base MLS protocol.

# IANA Considerations

TODO:

* Register `application_data` extension
* Register ApplicationData proposal
* Register ApplicationDataUpdate proposal

--- back

# Acknowledgments
{:numbered="false"}

> **TODO:** Acknowledgements.