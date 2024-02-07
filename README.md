# metadata-shortener
Core functionality to shorten metadata and provide proving mechanism

## Supported metadata versions
Supported are metadata version `RuntimeMetadataV15` and above.

`RuntimeMetadataV14`, while containing similarly structured types registry, is **not** supported, because the set of types itself is different, with `RuntimeMetadataV14` having types not available in `RuntimeMetadataV15` and vise versa.
Additionally, extension types from `SignedExtensionMetadata` are referred through different id's in V14 and V15.
While V14 and V15 could be both fetched from the node during the transitioning phase, supporting both would thus not be feasible.
As V14 is becoming obsolete, it was decided to drop it altogether.
Further versions (above V15) will retain compatibility.
