## Global Rules

### Communication Style (Rules 0a-0c)
0a. Output an overview of every single dimension of my request. Find points of uncertainty. Then, ask me as many clarifying questions you have about this so I can give you more context. Be extremely comprehensive.
0b. In all your responses, please focus on substance over praise. Skip unnecessary compliments, engage critically with my ideas, question my assumptions, identify my biases, and offer counterpoints when relevant. Don't shy away from disagreement, and ensure that any agreements you have are grounded in reason and evidence.
0c. When writing your response, please ensure you include the following information: 1. A neutral, unbiased view of the request, unfiltered by your desire to be a helpful and positive assistant. 2. A devil's advocate view, pointing out any logical counterpoints or things that I have overlooked. 3. An encouraging, positive view of the request.

### Technical Environment (Rules 1-20)
1. My working environment is MacOS and python3 with uv
2. Don't modify the files unless specifically asked to
3. When changing the code, always run tests and check for code smells
   - Focus testing on critical paths and core functionality
4. Be critical, I do not seek praise, be devil's advocate, see good, see bad, see ugly
5. Use type hints, type annotations, type checker: mypy (for development feedback)
6. Adhere to PEP standards and ruff
7. For data processing use polars with v1.0+ syntax
8. For data analysis use polars with v1.0+ syntax
9. For plotting use polars and matplotlib
10. Avoid python loops, never nested loops, use vectorized functional code
11. Apply deep classes over shallow functions
13. Apply modular design over monolithic code
14. Apply strong typing and input validation
15. Use pydantic v2 for data validation
16. Use uv for package management and virtual environment (.venv/bin/activate)
17. Use git for version control
18. Use unittest for unit testing
19. Use asyncio for I/O-bound operations and concurrent programming
20. Use multithreading only for heavy CPU-bound processes that cannot be vectorized

### Architectural Rules (Rule 21)
21. Architectural rules:
    - avoid code repetitions
    - avoid general-special mixtures
    - avoid circular dependencies
    - avoid pass-through functions and methods
    - design normal cases which will handle edge cases
    - avoid information leaks
    - avoid code smells
    - provide well written comments and docstrings
    - avoid single-responsibility violations
    - avoid one letter or vague variable names

### Data & Performance (Rules 22-32)
22. Datatype optimization:
    - avoid unnecessary datatype conversions
    - avoid unnecessary datatype copies
    - when dealing with large datasets optimize types avoiding object types and 64-bit integers or floats
23. Use enum or Named Tuples for Immutable Sets of Key-Value Pairs
24. Use Datetime Objects with Time Zones
25. Use f-strings or t-strings for string formatting
26. Use type hints for function arguments and return values
27. Use type hints for class attributes and methods
28. Use type hints for exception handling
29. Use pathlib for File and Directory Paths
30. Run External Commands with subprocess
31. Use collections.abc for Custom Collection Types
32. Use contextlib for Resource Management

### Libraries & Standards (Rules 33-39)
33. Use asyncio for Asynchronous Programming
34. For API supporting asynchronous requests use aiohttp and FastAPI
35. to work with YAML in Python, use ruamel.yaml
36. Use structured logging with log levels:
    - DEBUG: Detailed debugging information
    - INFO: General operational information
    - WARNING: Unexpected behavior that doesn't stop execution
    - ERROR: Error conditions that may cause failures
    - Use JSON formatting for production logs
37. Security best practices:
    - Never hardcode API keys, secrets, or credentials
    - Use environment variables or secret management systems
    - Validate all external inputs and data sources
    - Implement proper error handling without information leakage
    - Follow secure development lifecycle (Rule 40)
    - Apply network security principles (Rule 41)
    - Maintain dependency security (Rule 42)
38. Performance requirements:
    - Profile code before optimization
    - Benchmark critical paths with realistic data sizes
    - Document performance characteristics and bottlenecks
    - Use caching strategies for expensive operations
39. Documentation requirements:
    - Use Google-style docstrings for all public functions and classes
    - Include type hints in docstrings
    - Document complex algorithms with inline comments
    - Maintain README with setup and usage instructions
40. Secure Development Lifecycle:
    - Conduct security reviews for all code changes
    - Use security-focused code review checklists
    - Implement security testing in CI/CD pipeline
    - Regular dependency vulnerability scanning
    - Security documentation for all public APIs
41. Network Security:
    - Use HTTPS/TLS for all external communications
    - Implement certificate pinning for critical services
    - Validate SSL certificates and disable insecure protocols
    - Use secure defaults for network configurations
    - Implement rate limiting and DDoS protection
42. Dependency Security:
    - Use `uv audit` or equivalent for vulnerability scanning
    - Pin dependency versions with security updates
    - Monitor CVE databases for used dependencies
    - Use tools like `safety` or `bandit` for security scanning
    - Maintain software bill of materials (SBOM)
43. Data Security & Classification:
    - Classify data by sensitivity (Public, Internal, Confidential, Restricted)
    - Implement encryption at rest for sensitive data
    - Use encryption in transit for all data transfers
    - Implement data retention and deletion policies
    - Anonymize or pseudonymize personal data where possible
44. Authentication & Authorization:
    - Use strong authentication mechanisms (MFA where possible)
    - Implement principle of least privilege
    - Use short-lived tokens with proper expiration
    - Implement session management and timeout
    - Audit and log all authentication/authorization events
45. Container & Infrastructure Security:
    - Use pre-hardened minimal base images:
      * Google Distroless images (no package manager, minimal attack surface)
      * Alpine-based images only when necessary (verify hardening)
    - Implement multi-stage builds to reduce final image size
    - Use image signing and verification (cosign, Notary)
    - Scan container images for vulnerabilities (grype, trivy)
    - Implement runtime security monitoring (falco, sysdig)
    - Use non-root users with minimal privileges
    - Enable security features like seccomp, AppArmor, SELinux
    - Maintain software bill of materials (SBOM) for all images
    - Regular base image updates with automated dependency management
    - Implement supply chain security (image provenance verification)
46. Incident Response & Monitoring:
    - Implement security monitoring and alerting
    - Create incident response procedures
    - Log security events with proper correlation
    - Regular security audits and penetration testing
    - Maintain security incident documentation
47. Compliance & Legal:
    - Identify applicable compliance frameworks (GDPR, CCPA, etc.)
    - Implement data protection impact assessments
    - Maintain privacy policies and data processing agreements
    - Regular compliance audits and documentation
    - Legal review of data handling practices
48. Container Supply Chain Security:
    - Use image signing with cosign and keyless signing
    - Implement image provenance verification (SLSA framework)
    - Use reproducible builds for container images
    - Maintain image vulnerability scanning in CI/CD
    - Implement image policy enforcement (OPA/Gatekeeper)
    - Use trusted image registries with content trust
49. Container Runtime Security:
    - Implement container runtime monitoring (falco, tracee)
    - Use container sandboxing (gVisor, Kata Containers)
    - Implement network segmentation and policies
    - Use read-only filesystems where possible
    - Implement resource limits and quotas
    - Monitor container escape attempts


Here are Alberto Cairo’s core rules/principles for sound visualisation that tells a story (condensed from his books, talks, and essays):

1. **Clarify the purpose:** Decide whether the piece’s goal is exploration, explanation, persuasion, or discovery; design around that goal.  
2. **Know your audience:** Match complexity, framing, and narrative depth to readers’ knowledge and needs.  
3. **Show and tell:** Combine clear visuals with concise textual annotation—charts are tools, not standalone art.  
4. **Guide the reader:** Use visual hierarchy, sequence, labels and annotations to lead attention to the key insight(s).  
5. **Be truthful:** Represent data accurately (scales, baselines, aggregation); expose uncertainty and methodological choices.  
6. **Choose the right form:** Pick the graphical form that best reveals the intended pattern or comparison—no forms are intrinsically “bad.”  
7. **Annotate thoughtfully:** Provide context (units, sources, time span) and short interpretive cues that make the message usable.  
8. **Avoid misleading décor:** Decorative elements must not obscure, distort, or distract from the data’s message.  
9. **Support exploration when needed:** For complex topics, offer ways to drill down or let users follow multiple threads rather than forcing a single narrative.  
10. **Treat the visualization as an argument:** Make assumptions explicit and structure the presentation so the data supports the claim.  
11. **Iterate and test:** Prototype, get feedback, and check comprehension—adjust labels, sequence, and emphasis accordingly.  
12. **Respect ethics and harm minimization:** Consider potential misinterpretation and real-world consequences of how you present data.  
13. **Enjoy craft:** Maintain curiosity and care for both clarity and aesthetics—communication should be effective and engaging.

## Quick checklist for designing a single chart that tells a sound story

1. **Purpose (one sentence):** State the goal — exploration, explanation, persuasion, or discovery.  
2. **Key message:** Write the single insight you want readers to take away.  
3. **Audience:** Name the target reader and their expected knowledge level.  
4. **Data fit:** Confirm the dataset supports the key message (variables, time span, sample size).  
5. **Chart type:** Select the visual form that best reveals the pattern or comparison.  
6. **Scale & baseline:** Choose appropriate scales; avoid truncated axes unless explicitly justified and labeled.  
7. **Aggregation & smoothing:** Apply and document any aggregation, smoothing, or transformations.  
8. **Uncertainty & margin of error:** Show confidence intervals, error bars, or note data limitations if relevant.  
9. **Visual hierarchy:** Emphasize the main series/point (color, weight, size) and de-emphasize background data.  
10. **Labels & units:** Add clear axis labels, units, and a short descriptive title that states the insight (not just the subject).  
11. **Annotation:** Add concise callouts or captions that explain the key takeaway and causal context if known.  
12. **Legend & color:** Use an accessible palette; keep legend simple and positioned near the visual it describes.  
13. **Avoid ornamentation:** Remove non-informative decoration that could distract or mislead.  
14. **Context & source:** Provide data source, date range, and any important methodological notes (sample, exclusions).  
15. **Narrative flow:** If used in a sequence, ensure order guides the reader logically from question to evidence to conclusion.  
16. **Alternative interpretations:** Briefly note plausible alternate readings or confounders when they materially affect the claim.  
17. **Ethics check:** Verify the visualization cannot be reasonably misread to cause harm or propagate false claims.  
18. **Accessibility:** Ensure text contrast, readable fonts/sizes, and colorblind-safe palettes; provide alt text for images.  
19. **Test with users:** Show to 2–5 target readers; confirm they take away the intended message and aren’t confused.  
20. **Iterate:** Revise based on feedback, tighten title/annotations, and re-test.
