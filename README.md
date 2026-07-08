# Encrypted Geometry Stack

## Thesis

A 3D model becomes a programmable economic asset only when Python controls STL encryption/decryption through data structures that decide who can reveal, modify, print, or verify each geometric layer.

## The System

The system converts a 3D STL file into a structured geometry stack: vertices, faces, normals, print layers, support regions, and critical design features are parsed by Python, stored in specialized data structures such as hash maps, Merkle trees, priority queues, and adjacency graphs, then selectively encrypted. Instead of encrypting the whole STL as one blob, the system encrypts each structural component according to its role: outer shell, internal lattice, hidden watermark, mechanical joint, or high-value manufacturing secret. A user with the right key can decrypt only the allowed region, while Python verifies integrity, reconstructs the mesh, detects tampering, and exports a printable STL. The result is not just file protection; it is programmable access control for physical geometry.

## Interdependence proof
Remove Python: The system loses the programmable parser, encryption pipeline, mesh reconstruction logic, permission engine, and STL exporter. The encrypted geometry stack becomes inert data with no execution layer.
Remove 3D STL Encrypt/Decrypt: The system becomes only a mesh-processing tool. It can organize geometry, but it cannot protect intellectual property, control manufacturing access, or selectively reveal printable design regions.
Remove Data Structure: The system collapses into crude whole-file encryption. Without graphs, trees, queues, indexes, and maps, Python cannot separate mesh regions, preserve relationships between faces and vertices, verify integrity, or decrypt geometry by permission layer.

## Failure mode

An attacker steals keys, reconstructs geometry from decrypted print paths, or exploits weak region segmentation to infer hidden internal structures.
A corrupted data structure can break mesh topology, causing decrypted models to become unprintable, unsafe, or geometrically invalid.

## Open question

Can encrypted STL meshes support zero-knowledge proof of printability without revealing the protected geometry?

## Implementation Sketch

The system loads an STL file in Python and separates the file into two layers: the **format layer** and the **geometry layer**. The format layer contains the STL structure itself: header, triangle count, `facet normal`, `outer loop`, `vertex`, `endloop`, and binary triangle records. This layer is preserved so the encrypted STL remains a valid STL file. The geometry layer contains the numeric data: vertex coordinates, normals, triangle positions, and optional region metadata. Only this numeric geometry layer is encrypted.

Python parses the STL into a mesh data structure where vertices, triangles, normals, edges, and regions are stored in structured forms such as arrays, hash maps, adjacency graphs, and Merkle trees. Each triangle is indexed, each vertex is mapped to its connected faces, and each region is grouped by function: outer shell, internal lattice, mechanical joint, support geometry, watermark, or protected design feature. The data structure becomes the control system that decides which numeric values are transformed, in what order, and under which key.

The encryption does not convert the STL into unreadable random bytes. Instead, Python applies a reversible keyed numeric transformation to the coordinates and normals. For example, every vertex coordinate is shifted, rotated, scaled, or noise-distorted using a deterministic key-generated mask. The result is still valid floating-point geometry, so any STL viewer can open it. However, the model appears visually corrupted: surfaces explode, proportions collapse, internal structures scatter, and the object becomes mechanically useless. The encrypted STL is viewable but not manufacturable.

For binary STL files, Python preserves the 80-byte header, triangle count, and 50-byte triangle record structure. It only modifies the 32-bit floating-point numbers representing normals and vertex coordinates. For ASCII STL files, Python preserves all STL keywords and rewrites only the numeric literals after `facet normal` and `vertex`. This guarantees that the encrypted output remains syntactically valid STL.

To decrypt, Python reloads the encrypted STL, rebuilds the same mesh data structures, regenerates the exact numeric masks from the secret key, and applies the inverse transformation. Because every triangle, vertex, and region has a stable index in the data structure, the system knows exactly which numbers to reverse. If the key is correct, the messy encrypted geometry returns to the original printable model. If the key is wrong, the STL remains viewable but geometrically broken.

The system also stores integrity proofs in a Merkle tree so Python can detect whether someone modified the encrypted STL before decryption. If even one triangle’s numeric values are tampered with, the hash proof fails, and the system refuses to reconstruct the original model. This turns the STL into a protected physical design file: visible enough for preview, corrupted enough to prevent theft, and reversible only through the correct key and data-structure-guided decryption.

