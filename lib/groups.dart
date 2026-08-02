/// Shared end-to-end-encrypted group membership: models, key rotation,
/// manifests, and the signed ownership charter.
///
/// Re-exports the `identity` package (crypto primitives, `Identity`, and the
/// libsodium types) since this layer's public API is built on it — consumers
/// need only depend on `groups`.
library;

export 'package:identity/identity.dart';

export 'src/group.dart';
export 'src/group_service.dart';
export 'src/ownership_charter.dart';
