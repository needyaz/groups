## 0.1.0

- Initial extraction from Mylo (`models/group.dart`, `services/group_service.dart`,
  `crypto/ownership_charter.dart`).
- Generic `Group` / `GroupMember` models, the 8 generic `GroupService` methods
  (create / add / remove+rotate / transfer / manifest DH crypto / group-key blob
  crypto), and the signed ownership charter (genesis + transfer links + validator).
- Location-domain methods (location/places/share-session/event blobs) dropped;
  replaced by generic `encryptWithGroupKey` / `decryptWithGroupKey`.
- Charter signing domain lifted to a `signingKeyDomain` parameter (was hardcoded).
- Depends on the `identity` package for crypto primitives + `Identity`.
