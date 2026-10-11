"""Threat parameter calibration RAG system.

Purpose-built RAG pipeline for extracting reachability, detectability,
and exploit maturity distribution parameters from threat intelligence
reports (DBIR, M-Trends, Sonatype SOTSC, ENISA TL, etc.).

Architecture:
    - Local sentence-transformers for embeddings
    - ChromaDB for vector storage (no server, file-based)
    - OpenAI-compatible API (LM Studio) for generation
    - Structured YAML output per (finding, context, parameter)
"""
