import 'dart:convert';
import 'dart:typed_data';

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

  const GroupMember({
    required this.uid,
    required this.publicKeyB64,
    this.edPubKeyB64,
    this.displayName,
    this.localDisplayName,
    this.avatarEmoji,
    this.avatarPhotoPath,
    this.avatarPlain = false,
  });

  Uint8List get publicKey => Uint8List.fromList(base64.decode(publicKeyB64));

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
  Map<String, dynamic> toManifestJson() => {
        'uid': uid,
        'publicKeyB64': publicKeyB64,
        if (edPubKeyB64 != null) 'edPubKeyB64': edPubKeyB64,
        if (displayName != null) 'displayName': displayName,
      };

  /// For local on-device storage — includes local-only fields.
  Map<String, dynamic> toJson() => {
        ...toManifestJson(),
        if (localDisplayName != null) 'localDisplayName': localDisplayName,
        if (avatarEmoji != null) 'avatarEmoji': avatarEmoji,
        if (avatarPhotoPath != null) 'avatarPhotoPath': avatarPhotoPath,
        if (avatarPlain) 'avatarPlain': true,
      };

  factory GroupMember.fromJson(Map<String, dynamic> j) => GroupMember(
        uid: j['uid'] as String,
        publicKeyB64: j['publicKeyB64'] as String,
        edPubKeyB64: j['edPubKeyB64'] as String?,
        displayName: j['displayName'] as String?,
        localDisplayName: j['localDisplayName'] as String?,
        avatarEmoji: j['avatarEmoji'] as String?,
        avatarPhotoPath: j['avatarPhotoPath'] as String?,
        avatarPlain: j['avatarPlain'] as bool? ?? false,
      );

  GroupMember copyWith({
    String? edPubKeyB64,
    String? displayName,
    String? localDisplayName,
    String? avatarEmoji,
    String? avatarPhotoPath,
    bool? avatarPlain,
  }) =>
      GroupMember(
        uid: uid,
        publicKeyB64: publicKeyB64,
        edPubKeyB64: edPubKeyB64 ?? this.edPubKeyB64,
        displayName: displayName ?? this.displayName,
        localDisplayName: localDisplayName ?? this.localDisplayName,
        avatarEmoji: avatarEmoji ?? this.avatarEmoji,
        avatarPhotoPath: avatarPhotoPath ?? this.avatarPhotoPath,
        avatarPlain: avatarPlain ?? this.avatarPlain,
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

  /// Signed ownership charter (delegation chain). Null for groups created before
  /// charters existed, or not yet backfilled. Carried in the manifest (so every
  /// member holds it) and persisted locally as the parsed JSON chain
  /// (`[{payload, sig}, …]`).
  final List<Object?>? charter;

  const Group({
    required this.groupId,
    required this.name,
    required this.ownerUid,
    required this.members,
    required this.groupKey,
    required this.createdAt,
    this.manifestUpdatedAt = 0,
    this.charter,
  });

  Group copyWith({
    String? name,
    String? ownerUid,
    List<GroupMember>? members,
    Uint8List? groupKey,
    int? manifestUpdatedAt,
    List<Object?>? charter,
  }) =>
      Group(
        groupId: groupId,
        name: name ?? this.name,
        ownerUid: ownerUid ?? this.ownerUid,
        members: members ?? this.members,
        groupKey: groupKey ?? this.groupKey,
        createdAt: createdAt,
        manifestUpdatedAt: manifestUpdatedAt ?? this.manifestUpdatedAt,
        charter: charter ?? this.charter,
      );

  GroupMember? memberByUid(String uid) {
    for (final m in members) {
      if (m.uid == uid) return m;
    }
    return null;
  }

  /// For the server: excludes local-only fields; uses toManifestJson for members.
  Map<String, dynamic> toManifestJson() => {
        'groupId': groupId,
        'name': name,
        'ownerUid': ownerUid,
        'members': members.map((m) => m.toManifestJson()).toList(),
        'groupKey': base64.encode(groupKey),
        'createdAt': createdAt,
        if (charter != null) 'charter': charter,
      };

  /// For local storage: manifest fields + local-only fields.
  Map<String, dynamic> toJson() => {
        ...toManifestJson(),
        // Local storage uses full member JSON (includes local-only fields).
        'members': members.map((m) => m.toJson()).toList(),
        if (manifestUpdatedAt > 0) 'manifestUpdatedAt': manifestUpdatedAt,
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
      createdAt: j['createdAt'] as int,
      manifestUpdatedAt: j['manifestUpdatedAt'] as int? ?? 0,
      charter: rawCharter is List ? rawCharter.cast<Object?>() : null,
    );
  }
}
