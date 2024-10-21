---
title: "Using Messaging Layer Security to Modify GroupContext Extensions"
abbrev: "MLS GroupContext diffs"
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

One feature that the Messaging Layer Security (MLS) protocol provides is that it
allows the members of a group to confirm that they agree on certain data.
MLS includes a mechanism to modify this data (the GroupContext) all at once,
but not to modify it individually. In this document, we define a mechanism
that allows implementations to add, update, and remove each element of the
GroupContext individually. This also makes it practical for applications
using MLS to exploit this feature of MLS to ensure that the group members
are in agreement on the state of the application in addition to MLS-related state.

--- middle

# Introduction

Messaging Layer Security (MLS) allows a group of clients to authenticate each
other and establish shared secret state {{!RFC9420}}.  One of the primary
security benefits of MLS is that the MLS key schedule confirms that the group
agrees on certain metadata, such as the membership of the group. Members that
disagree on the relevant metadata will arrive at different keys and be unable to
communicate. Applications based on MLS can integrate their state into this
metadata in order to confirm that the members of an MLS group agree on
application state as well as MLS metadata.

Unfortunately this state can only be modified using the
GroupContextExtensions Proposal, which needs to include the entire
GroupContext. This may include dozens of individual extensions and may be
quite large. MLS clients should be able to modify orthogonal aspects of the
GroupContext in separate Proposals and should not need to send large
amounts of data for a small change.

Here, we define a new MLS proposal type GroupContextExtensionsDiff. This proposal type allows modification on a per extension basis. It also allows GroupContext extensions to define simple diff formats (for example, to add, remove, and update elements in a list or items in a map).

# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document uses many terms from {{!RFC9420}}. Some of these have
names which are similar or may be confusing: GroupContext, GroupContext
extension, ExtensionType, and GroupContextExtensions proposal.

# GroupContext extensions modification

This document defines a new GroupContextExtensionsDiff proposal. It
is not a Safe Extension as defined in {{Section 2 of
!I-D.ietf-mls-extensions}}, because it can modify any GroupContext
extension, including those defined in {{!RFC9420}}. It is intended as a
complete replacement for the GroupContextExtensions Proposal.
The GroupContextExtensionsDiff proposal does not require an UpdatePath,
and may be included in external proposals.

~~~ tls
enum {
    remove(0),
    add(1),
    replace(2),
    diff(3),
    (255)
} OperationType;

uint8 DiffType;

struct {
    ExtensionType group_context_extension;
    OperationType operation;
    select (operation) {
        case remove:
            struct {};
        case add:
            opaque extension_data<V>;
        case replace:
            opaque extension_data<V>;
        case diff:
            opaque diff_data<V>;
    };
} ExtensionDiff;

struct {
    ExtensionDiff group_context_extension_diffs<V>;
} GroupContextExtensionsDiff;
~~~

The semantics of OperationType are as follows:

- `remove` means that the GroupContext extension was present, and will be
completely absent from the GroupContext.
- `add` means that the GroupContext extension was absent, and will be
present with the value provided in `extension_data`.
- `replace` means that the GroupContext extension was present and will
be completely replaced with the new value in `extension_data`
- `diff` means that the GroupContext extension will be modified according
to the diff format defined by that extension. (Two concrete diff formats are
defined in {{diff-formats}} which extension designers are free to use or
not use.)


## Processing rules

A single GroupContextExtensionsDiff proposal can contain changes to multiple
extensions. Likewise a single Commit can include multiple
GroupContextExtensionsDiff proposals, however a single Commit MUST NOT
include multiple GroupContextExtensionsDiff proposals which refer to the
same ExtensionType. A GroupContextExtensions proposal MUST NOT appear in a
commit with any GroupContextExtensionsDiff proposal.

The motivation for allowing multiple extensions in a single
GroupContextExtensionsDiff proposal is to allow a client to modify multiple
extensions in a single "transaction". A common example of this is to add a
GroupContext extension while also adding that extension to the
`required_capabilities` GroupContext extension.

A proposal which removes a GroupContext extension that is present in the
`required_capabilities` list is invalid. Adding a required capability that is
not supported by all group members is already forbidden by {{!RFC9420}}.


# Diff Formats

## List Diff Format

**TODO**

## Map Diff Format

**TODO**

# Previous draft contents

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
and change control properties to the state information it manages.
No unauthorized parties can make changes to the GroupContext, and the
identity of the group member making each change is authenticated.

The data synchronized via this mechanism may or may not be confidential to
the group, depending on whether the GroupContextExtensionsDiff proposal is
sent as
an MLS PublicMessage or PrivateMessage.  As with application data, applications
should generally prefer the use of Private Message.  There may be cases,
however, where it is useful for intermediaries to inspect application state
updates, e.g., to enforce policy.

# IANA Considerations

## GroupContextExtensionDiff Proposal

The `gce_diff` MLS Proposal Type is used to update Group Context Extensions
in a group more efficiently than using a `group_context_extensions` proposal
type. The `gce_update` type is updating rather than replacing the extensions.

* Value: 0x000d
* Name: gce_diff
* Recommended: Y
* External: Y
* Path Required: N

## Change to the MLS Extension Types registry

This document adds a "Diff" column to the MLS Extension Types registry. In
the registration template this will be referred to as "Diff Type". The value
value can be "-" indicating no Diff Types are supported, or a value present
in the GroupContext Diff Types registry.

## GroupContext Diff Types registry

The "MLS GroupContext Diff Types" registry lists identifiers for types of
difference algorithms to be applied to GroupContext extension data. The
diff type field is one byte wide, so valid values are in the range 0x00 to
0xFF.

Template:

- Value: The numeric value of the diff type
- Name:  The name of the diff type
- Recommended: Same as in Section 17.1 of {{!RFC9420}}
- Reference: The document where this extensions is defined

Initial contents:

| Value | Name     | R | Ref      |
|-------+----------+---+----------|
| 0x00  | reserved | - | RFC XXXX |
| 0x01  | list     | Y | RFC XXXX |
| 0x02  | map      | Y | RFC XXXX |


--- back

# Acknowledgments
{:numbered="false"}

> **TODO:** Acknowledgements.
