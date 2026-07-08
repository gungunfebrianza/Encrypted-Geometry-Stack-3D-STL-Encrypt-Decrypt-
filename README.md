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
