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
advantage of the state agreement properties of MLS:

- An ApplicationData proposal type that enables arbitrary application data to
  be associated to a Commit.

- An `application_state` group context extension that associates application
  state with an epoch of the group.

As with the above, information carried in these proposals and extension marked
as belonging to a specific application component, so that components can manage
their information independently.

The separation between components is acheived by the application assigning each
component a unique component ID number.  These numbers are then incorporated
into the appopriate calculations in the protocol to achieve the required
separation.

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

## Hybrid Public Key Encryption (HPKE) Keys

## Signature Keys

## Pre-Shared Keys

## Exported Secrets

## Application State Agreement

By virtue of the synchronizations requirements discussed in {{Section 14 of
RFC9420}} and the group agreement properties of MLS, MLS Commits already provide
a synchronization point for one aspect of the application, namely the MLS-level
membership.  In this section, we introduce additional mechanisms that allow an
application to use MLS Commits to synchronize other aspects of its state.

We provide two basic mechanisms, one ephemeral and one persistent:

* The ApplicationData proposal type allows an application component to associate
  application data to a Commit, so that the member processing the Commit knows
  that all other group members will be processing the same data.

* The `application_state` GroupContext extension provides confirmation that all
  group members have the same representation of the application's state.  The
  ApplicationStateUpdate proposal allows members to update this state
  information.

An application can use these two mechanisms to efficiently keep the group in
sync with regard to application state, even if that state is very large.  For
example, suppose an application has an application-level participant list, on
which all members should agree, and a format for patches to the participant list
reflecting application-level adds and removes.  The application could use the
mechansism in this section to manage the participant list in the following way:

* Group members can propose changes to the participant list by sending patches
  in ApplicationData proposals for the "participant list" component.

* When a group member wishes to put a set of changes into effect, they prepare a
  Commit in the following way:
    * Select a set of ApplicationData proposals reflecting accepted patches.
    * Apply the patches to the committer's local participant list.
    * Compute a hash of the participant list.
    * Add an ApplicationStateUpdate setting the state for the "participant list"
      component to the new participant list hash.

* When a group member receives such a Commit, the process it in the following
  way:
    * Identify the ApplicationData proposals for the "participant list"
      component.
    * Extract the patches from these proposals and apply them to the member's
      local copy of the participant list.
    * Compute a hash of the updated participant list.
    * Verify that hash matches the new value in the `application_state`
      extension for the "participant list" component.

Note that this approach can manage an arbitrarily large participant list, while
only sending patches and hashes.  A new joiner can also verify that they have
received the correct participant list for the group by comparing its local copy
to the hash in the `application_state` extension.

### ApplicationData

The ApplicationData proposal type allows an application component to send
application data that will be associated the Commit that applies the propsal.

```
struct {
    ComponentID component_id;
    opaque application_data<V>;
} ApplicationData;
```

An ApplicationData proposal is invalid if its `component_id` references a
component that is not known to the application.

> TODO: Do we need an `application_components` extension or something so that
> the MLS stack can do this filtering?

ApplicationData proposals are processed after any default proposals (i.e., those
defined in {{RFC9420}}), but before any ApplicationStateUpdate proposals.

A client applies an ApplicationData proposal by providing the contents of the
`application_data` field to the component identified by the `component_id`.  If
a Commit references more than one ApplicationData proposal for the same
`component_id` value, then they MUST be processed in the order in which they are
specified in the Commit.

### The `application_state` Extension

The `application_state` extension is a group context extension that stores a
representation of application components' state.  Its contents are managed by
the ApplicationStateUpdate proposal, as specified in {{applicationstateupdate}}.

```
struct {
    ComponentID component_id;
    opaque state<V>;
} ComponentState;

struct {
    ComponentState component_states<V>;
} ApplicationState;
```

The entries in the `component_states` vector MUST be sorted by `component_id` in
numerically ascending order.  There MUST NOT be more than one entry per
`component_id`.

The `application_state` extension MUST always be the last extension in the
`extensions` list in the GroupContext.

Note that this extension is included in every Welcome message, and the only way
to update a `state` value is to replace it entirely.  If a `state` value is
large, it will result in large Welcome and ApplicationStateUpdate messages.  In
cases where a component's state does not have a fixed or bounded size,
application designers should instead use a hash of the state in this extension,
and use application-level mechanisms to distribute the state.

### ApplicationStateUpdate

An ApplicationData proposal allows an application component to send application
data that will be associated the Commit that applies the propsal.  Since MLS
Commits already provide a synchronization point for one aspect of the
applicaiton (the MLS-level membership), this mechanism allows the application to
use MLS proposals to synchronize the group on other aspects of the application.

```
enum {
    invalid(0),
    set(1),
    remove(2),
    (255)
} ApplicationStateUpdateOperation;

struct {
    ComponentID component_id;
    ApplicationStateUpdateOperation op;

    select (ApplicationStateUpdate.op) {
        case set: opaque new_state<V>;
        case remove: struct{}
    }
} ApplicationStateUpdate;
```

An ApplicationStateUpdate proposal is invalid if its `component_id` references a
component that is not known to the application, or if it specifies the removal
of state for a `component_id` that has no state present.  A proposal list is
invalid if it includes multiple ApplicationStateUpdate proposals referencing the
same `component_id`.

> TODO: See above comment about the MLS stack enforcing "known to the
> application.

> TODO: Deconflict with GroupContextExtensions.

ApplicationStateUpdate proposals are processed after any default proposals (i.e., those
defined in {{RFC9420}}), and any ApplicationData proposals.

A client applies an ApplicationStateUpdate proposal by changing the contents of
the `application_state` extension associated to its local copy of the
GroupContext for the group.

* If no `application_state` extension is present in the GroupContext, add one to
  the end of the `extensions` list in the GroupContext.

* If the `op` field is set to `set`:
    
    * If there is an entry in the `component_states` vector in the
      `application_state` extension with the specified `component_id`, then set
      its `state` field to the specified `new_state`.

    * Otherwise, insert a new entry in the `component_states` vector with the
      specified `component_id` and the `state` field set to the `new_state`
      value.  The new entry is inserted at the proper point to keep the
      `component_states` vector sorted by `component_id`.

* If the `op` field is set to `remove`:

    * If there is an entry in the `component_states` vector in the
      `application_state` extension with the specified `component_id`, remove
      it.

    * Otherwise, the proposal is invalid.

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

* Register ApplicationData proposal
* Register ApplicationStateUpdate proposal
* Register application_state extension
* Create component ID registry?

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
