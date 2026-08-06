import 'dart:convert';
import 'dart:typed_data';

/// A member's standing role within a group. String-backed (like other wire
/// enums) so an older client that doesn't know a future role reads it as the
/// safe default rather than crashing.
///
/// [member] is the implicit default for every roster, and the value an absent
/// `role` key deserializes to. The richer owner/co-owner distinction is app
/// policy: an app may grant owners and co-owners full content access (every
/// item's keys, including hidden ones) while plain members have no standing
/// content access.
///
/// Note: ownership truth lives in [Group.ownerUid] (and the charter tip), NOT
/// in this field. [owner] exists only so a UI can render the roster uniformly;
/// never read ownership from a member's role.
enum GroupRole { member, coOwner, owner }

GroupRole _roleFromName(String? name) {
  switch (name) {
    case 'coOwner':
      return GroupRole.coOwner;
    case 'owner':
      return GroupRole.owner;
    default:
      // null (pre-roles manifests) and any unknown future value → member.
      return GroupRole.member;
  }
}

class GroupMember {
  final String uid;
  final String publicKeyB64;

  /// The member's Ed25519 charter-signing public key (base64), learned from
  /// their piggybacked publishes. The owner needs it to name this member as the
  /// new owner in a transfer-link. Null until first seen.
  final String? edPubKeyB64;

  /// Self-reported display name, synced from the group manifest.
  final String? displayName;

  /// Local-only override: how THIS device labels this member. Never published.
  final String? localDisplayName;

  /// Local-only per-group avatar emoji override. Never published. Stored in
  /// local group JSON and included in backups.
  final String? avatarEmoji;

  /// Local-only per-group avatar photo path. File path on this device only;
  /// backups store the bytes instead of the path. Never published.
  final String? avatarPhotoPath;

  /// Local-only "plain" override: when true, this device shows the member as
  /// initials on their assigned color, suppressing any published photo. Never
  /// published. Mutually exclusive with [avatarPhotoPath] / [avatarEmoji].
  final bool avatarPlain;

  /// The member's standing role in the group. Defaults to [GroupRole.member].
  /// Published in the manifest only when non-default, so role-less rosters
  /// serialize byte-for-byte as before (see [toManifestJson]).
  final GroupRole role;

  /// Opaque unknown-field passthrough, LOCAL-ONLY. [fromJson] captures any key
  /// it doesn't recognize here; [toJson] re-emits them verbatim so an adopter's
  /// app-specific per-member fields (e.g. a local alert threshold) survive a
  /// round-trip through this model without the package knowing what they mean.
  ///
  /// Never emitted by [toManifestJson]: a member entry's unrecognized keys must
  /// not silently ride the wire. To drop a key, [copyWith] with a map that
  /// omits it. An empty map serializes to nothing — output is byte-identical to
  /// a pre-passthrough client.
  final Map<String, Object?> extra;

  const GroupMember({
    required this.uid,
    required this.publicKeyB64,
    this.edPubKeyB64,
    this.displayName,
    this.localDisplayName,
    this.avatarEmoji,
    this.avatarPhotoPath,
    this.avatarPlain = false,
    this.role = GroupRole.member,
    this.extra = const {},
  });

  Uint8List get publicKey => Uint8List.fromList(base64.decode(publicKeyB64));

  /// True when this member is a co-owner (full content access, equal to owner,
  /// but not the billing party and cannot transfer ownership).
  bool get isCoOwner => role == GroupRole.coOwner;

  /// The local-view avatar photo path for this member: a local override photo
  /// wins, else the member's received published photo ([receivedPath]). Returns
  /// null — meaning "show initials on the assigned color" — when the viewer has
  /// chosen the "plain" override or there is no photo at all.
  String? resolvedAvatarPath(String? receivedPath) {
    if (avatarPlain) return null;
    return avatarPhotoPath ?? receivedPath;
  }

  String get name {
    if (localDisplayName != null && localDisplayName!.isNotEmpty) {
      return localDisplayName!;
    }
    if (displayName != null && displayName!.isNotEmpty) return displayName!;
    return '${uid.substring(0, 8)}…${uid.substring(uid.length - 4)}';
  }

  /// For the encrypted manifest sent to the server and other members.
  ///
  /// `role` is emitted ONLY when non-default. This is a load-bearing
  /// backward-compat rule: a pure-member roster (every pre-roles manifest)
  /// serializes exactly as before, so adopters and any canonical-JSON
  /// consumers see no wire change.
  Map<String, dynamic> toManifestJson() => {
        'uid': uid,
        'publicKeyB64': publicKeyB64,
        if (edPubKeyB64 != null) 'edPubKeyB64': edPubKeyB64,
        if (displayName != null) 'displayName': displayName,
        if (role != GroupRole.member) 'role': role.name,
      };

  /// For local on-device storage — includes local-only fields and the [extra]
  /// passthrough. Recognized keys always win: an [extra] entry can never shadow
  /// a real field (only reachable via constructor misuse — [fromJson] never
  /// captures recognized keys — but this model feeds the trust boundary, so
  /// the guard is unconditional).
  Map<String, dynamic> toJson() {
    final j = <String, dynamic>{
      ...toManifestJson(),
      if (localDisplayName != null) 'localDisplayName': localDisplayName,
      if (avatarEmoji != null) 'avatarEmoji': avatarEmoji,
      if (avatarPhotoPath != null) 'avatarPhotoPath': avatarPhotoPath,
      if (avatarPlain) 'avatarPlain': true,
    };
    for (final e in extra.entries) {
      if (!_knownKeys.contains(e.key)) j.putIfAbsent(e.key, () => e.value);
    }
    return j;
  }

  /// Every key [fromJson] consumes into a real field. `'emoji'` is the legacy
  /// pre-rename spelling of `avatarEmoji` (see [fromJson]) — consumed, so it
  /// migrates rather than lingering in [extra].
  static const _knownKeys = {
    'uid',
    'publicKeyB64',
    'edPubKeyB64',
    'displayName',
    'localDisplayName',
    'avatarEmoji',
    'emoji',
    'avatarPhotoPath',
    'avatarPlain',
    'role',
  };

  factory GroupMember.fromJson(Map<String, dynamic> j) => GroupMember(
        uid: j['uid'] as String,
        publicKeyB64: j['publicKeyB64'] as String,
        edPubKeyB64: j['edPubKeyB64'] as String?,
        displayName: j['displayName'] as String?,
        localDisplayName: j['localDisplayName'] as String?,
        // `'emoji'` is a backward-compat read for local JSON written before the
        // `avatarEmoji` rename; nothing writes it anymore, so the next toJson()
        // migrates it forward.
        avatarEmoji: j['avatarEmoji'] as String? ?? j['emoji'] as String?,
        avatarPhotoPath: j['avatarPhotoPath'] as String?,
        avatarPlain: j['avatarPlain'] as bool? ?? false,
        role: _roleFromName(j['role'] as String?),
        extra: {
          for (final e in j.entries)
            if (!_knownKeys.contains(e.key)) e.key: e.value,
        },
      );

  /// [clearAvatarPhotoPath] resets the local photo override back to null —
  /// the `?? this` idiom can never do that, and a dangling override path (the
  /// file's container moved across an app update) must be droppable so the
  /// member falls back to their received photo.
  ///
  /// [extra] REPLACES the whole passthrough map when provided; pass a map
  /// omitting a key to clear that key.
  GroupMember copyWith({
    String? edPubKeyB64,
    String? displayName,
    String? localDisplayName,
    String? avatarEmoji,
    String? avatarPhotoPath,
    bool clearAvatarPhotoPath = false,
    bool? avatarPlain,
    GroupRole? role,
    Map<String, Object?>? extra,
  }) =>
      GroupMember(
        uid: uid,
        publicKeyB64: publicKeyB64,
        edPubKeyB64: edPubKeyB64 ?? this.edPubKeyB64,
        displayName: displayName ?? this.displayName,
        localDisplayName: localDisplayName ?? this.localDisplayName,
        avatarEmoji: avatarEmoji ?? this.avatarEmoji,
        avatarPhotoPath: clearAvatarPhotoPath
            ? null
            : (avatarPhotoPath ?? this.avatarPhotoPath),
        avatarPlain: avatarPlain ?? this.avatarPlain,
        role: role ?? this.role,
        extra: extra ?? this.extra,
      );
}

class Group {
  final String groupId;
  final String name;
  final String ownerUid;
  final List<GroupMember> members;

  /// 32-byte symmetric key used to encrypt this group's shared payloads. Never
  /// transmitted in plaintext; rotated on member removal.
  final Uint8List groupKey;
  final int createdAt;

  /// Epoch-ms timestamp of the last manifest publish or pull persisted locally.
  /// Lets a sync layer decide whether the server manifest is newer than local
  /// state. Local-only: never included in the manifest. Defaults to 0.
  final int manifestUpdatedAt;

  /// Signed ownership charter (delegation chain). Null for groups created
  /// before charters existed — such groups have no enforceable ownership proof
  /// and gain one only by being recreated. Carried in the manifest (so every
  /// member holds it) and persisted locally as the parsed JSON chain
  /// (`[{payload, sig}, …]`).
  final List<Object?>? charter;

  /// Opaque unknown-field passthrough, WIRE-VISIBLE. [fromJson] captures any
  /// key it doesn't recognize here; [toManifestJson] (and therefore [toJson])
  /// re-emits them verbatim, so an adopter's app-specific manifest fields
  /// (e.g. a group-level sharing mode) survive a republish through this model
  /// without the package knowing what they mean.
  ///
  /// Because these keys ride the encrypted manifest to every member, do NOT
  /// put local-only or device-private data here — that belongs in the app's
  /// own storage (or, per-member, in [GroupMember.extra], which is local-only).
  /// To drop a key, [copyWith] with a map that omits it. An empty map
  /// serializes to nothing — output is byte-identical to a pre-passthrough
  /// client, so adopters that never set it (and their peers) see no wire
  /// change.
  final Map<String, Object?> extra;

  const Group({
    required this.groupId,
    required this.name,
    required this.ownerUid,
    required this.members,
    required this.groupKey,
    required this.createdAt,
    this.manifestUpdatedAt = 0,
    this.charter,
    this.extra = const {},
  });

  /// [clearCharter] drops the charter instead of inheriting it — without it a
  /// stale charter can never be removed (`charter ?? this.charter` always
  /// resurrects it), which matters when a group's ownership has diverged from
  /// its chain and the caller wants to stop presenting an unenforceable chain.
  ///
  /// [extra] REPLACES the whole passthrough map when provided; pass a map
  /// omitting a key to clear that key.
  Group copyWith({
    String? name,
    String? ownerUid,
    List<GroupMember>? members,
    Uint8List? groupKey,
    int? manifestUpdatedAt,
    List<Object?>? charter,
    bool clearCharter = false,
    Map<String, Object?>? extra,
  }) =>
      Group(
        groupId: groupId,
        name: name ?? this.name,
        ownerUid: ownerUid ?? this.ownerUid,
        members: members ?? this.members,
        groupKey: groupKey ?? this.groupKey,
        createdAt: createdAt,
        manifestUpdatedAt: manifestUpdatedAt ?? this.manifestUpdatedAt,
        charter: clearCharter ? null : (charter ?? this.charter),
        extra: extra ?? this.extra,
      );

  GroupMember? memberByUid(String uid) {
    for (final m in members) {
      if (m.uid == uid) return m;
    }
    return null;
  }

  /// The billing/charter owner. Authoritative via [ownerUid] — never inferred
  /// from a member's [GroupRole].
  bool isOwner(String uid) => uid == ownerUid;

  /// A co-owner: full content access equal to the owner, but not the billing
  /// party. Derived from the member's role.
  bool isCoOwner(String uid) => memberByUid(uid)?.role == GroupRole.coOwner;

  /// The set allowed to see hidden items and hold every item's keys: the owner
  /// plus all co-owners. This is the policy boundary an app wraps item keys
  /// against for hidden/restricted content.
  bool canAccessHidden(String uid) => isOwner(uid) || isCoOwner(uid);

  /// The members who get full content access (owner + co-owners), as the
  /// recipient set for hidden item keys and co-owner escrow.
  List<GroupMember> get fullAccessMembers =>
      members.where((m) => isOwner(m.uid) || m.isCoOwner).toList();

  /// For the server: excludes local-only fields; uses toManifestJson for
  /// members; appends the [extra] passthrough. Recognized keys always win: an
  /// [extra] entry can never shadow a real field (only reachable via
  /// constructor misuse — [fromJson] never captures recognized keys — but this
  /// model feeds the trust boundary, so the guard is unconditional).
  Map<String, dynamic> toManifestJson() {
    final j = <String, dynamic>{
      'groupId': groupId,
      'name': name,
      'ownerUid': ownerUid,
      'members': members.map((m) => m.toManifestJson()).toList(),
      'groupKey': base64.encode(groupKey),
      'createdAt': createdAt,
      if (charter != null) 'charter': charter,
    };
    for (final e in extra.entries) {
      if (!_knownKeys.contains(e.key)) j.putIfAbsent(e.key, () => e.value);
    }
    return j;
  }

  /// For local storage: manifest fields + local-only fields.
  Map<String, dynamic> toJson() => {
        ...toManifestJson(),
        // Local storage uses full member JSON (includes local-only fields).
        'members': members.map((m) => m.toJson()).toList(),
        if (manifestUpdatedAt > 0) 'manifestUpdatedAt': manifestUpdatedAt,
      };

  /// Every key [fromJson] consumes into a real field.
  static const _knownKeys = {
    'groupId',
    'name',
    'ownerUid',
    'members',
    'groupKey',
    'createdAt',
    'manifestUpdatedAt',
    'charter',
  };

  factory Group.fromJson(Map<String, dynamic> j) {
    final rawCharter = j['charter'];
    return Group(
      groupId: j['groupId'] as String,
      name: j['name'] as String,
      ownerUid: j['ownerUid'] as String,
      members: (j['members'] as List<dynamic>)
          .map((e) => GroupMember.fromJson(e as Map<String, dynamic>))
          .toList(),
      groupKey: Uint8List.fromList(base64.decode(j['groupKey'] as String)),
      createdAt: _asInt(j['createdAt'])!,
      manifestUpdatedAt: _asInt(j['manifestUpdatedAt']) ?? 0,
      charter: rawCharter is List ? rawCharter.cast<Object?>() : null,
      extra: {
        for (final e in j.entries)
          if (!_knownKeys.contains(e.key)) e.key: e.value,
      },
    );
  }

  /// Tolerant [fromJson] for untrusted input (a decrypted peer manifest, a
  /// possibly-corrupt local record): returns null instead of throwing on a
  /// missing field, a wrong type, or malformed base64. Prefer this anywhere the
  /// JSON did not come from this device.
  static Group? tryFromJson(Map<String, dynamic> j) {
    try {
      return Group.fromJson(j);
    } catch (_) {
      return null;
    }
  }
}

/// Accepts an int, or a double/num that is exactly integral — JSON producers in
/// other languages emit `1.7e12` for a whole-number timestamp, which a bare
/// `as int` cast rejects with a TypeError.
int? _asInt(Object? v) {
  if (v is int) return v;
  if (v is num && v == v.roundToDouble() && v.abs() <= 9007199254740991) {
    return v.toInt();
  }
  return null;
}
