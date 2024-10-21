---
title: "Efficient Updates to Messaging Layer Security GroupContext Extensions"
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
MLS includes a mechanism to do a wholesale replacements of all GroupContext extensions,
but not to modify individual extensions. In this document, we define a mechanism
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

# GroupContextDiff

This document defines a new GroupContextExtensionsDiff proposal. It
is not a Safe Extension as defined in {{Section 2 of
!I-D.ietf-mls-extensions}}, because it can modify any GroupContext
extension, including those defined in {{!RFC9420}}.
The GroupContextExtensionsDiff proposal requires an UpdatePath,
and may be sent by an authorized external sender.

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

The following two subsections define two Diff Formats for very common
data structures.

Both of the Diff Formats defined below use the following struct for an
opaque byte string.

~~~ tls
struct {
  opaque element<V>;
} OpaqueElement;
~~~


## Map Diff Format

This Diff Format logically represents a map or dictionary that is not
allowed to have duplicate map keys.

~~~ tls
struct {
  opaque elementName<V>;
  opaque elementValue<V>;
} OpaqueMapElement;

struct {
      OpaqueElement removedKeys<V>;
      OpaqueMapElement newOrUpdatedElements<V>;
} MapDiff;
~~~

A diff using this format first removes all the keys in `removedKeys` and
than replaces or adds the elements in `newOrUpdatedElements`.

Removing a non-existant map key renders the diff and its proposal invalid.


## List Diff Format

This Diff Format logically represents changes to an ordered list.

~~~ tls
struct {
  uint32 index;
  opaque element<V>;
} ElementWithIndex;

struct {
  ElementWithIndex replacedElements<V>;
  uint32 removedIndices<V>;
  ElementWithIndex insertedElements<V>;
  OpaqueElement appendedEntries<V>;
} ListDiff;
~~~

A diff using this format first replaces all the elements (index-by-index) in
`replacedElements`, then the removes the elements in `removedIndices`
according to the then order of the array, then inserts all the elements in
`insertedElements` according to the then order of the array, then
finally appends the `appendedEntries` (in order). All indices are zero-based.

For the avoidance of doubt, two insertedElements with the same index will
cause the second inserted element to be *before* the first inserted element.

Attempting to insert or replace at a non-existing index renders the diff
and its proposal invalid.


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
type. The `gce_diff` type is updating rather than replacing the extensions.

* Value: 0x000d
* Name: gce_diff
* Recommended: Y
* External: Y
* Path Required: Y

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
