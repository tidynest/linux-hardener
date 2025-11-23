Phase 1: .claude/ Directory Files (14 files)

Priority 1 - Core Development Guides:
1. ARCHITECTURE.md - System design, verify matches current implementation
2. NAMING_CONVENTIONS.md - Verify all code follows these rules
3. CODE_PATTERNS.md - Check if patterns are still current
4. API_CONTRACTS.md - Verify trait definitions match implementation

Priority 2 - Project Management:
5. IMPLEMENTATION_PHASES.md - Check current phase status, update progress
6. PROGRESS.md - Update with latest completed work
7. NEXT_STEPS.md - Verify next steps are still relevant
8. SESSION_NOTES.md - Review for any pending items

Priority 3 - Reference Documents:
9. DISTRO_MATRIX.md - Distribution-specific information (should be stable)
10. SECURITY_CONTROLS.md - Hardening parameters catalogue (should be stable)
11. PLUGIN_MANAGER.md - Plugin manager documentation
12. QUICK_REFERENCE.md - Quick reference guide
13. README(_dot_claude).md - .claude directory explanation

Configuration:
14. settings.local.json - Local settings (just verify, don't change)

Phase 2: Root Documentation Files

15. CLAUDE.md - Main development instructions for Claude Code
16. README.md - Project README for users/developers
17. start.txt - Session startup context
18. fix_now.md - Current issues list (probably can be removed after our
    fixes)

Phase 3: Scripts Directory

19. scripts/README.md - Scripts documentation
20. scripts/validate_naming.py - Naming validation script

Review Checklist for Each File:

- ✅ Is information accurate and current?
- ✅ Does it match the actual codebase?
- ✅ Are there contradictions with other docs?
- ✅ Is anything outdated or redundant?
- ✅ Does it reflect our recent field naming refactoring?
- ✅ Are there any TODOs or placeholders?
- ✅ Is British English used consistently?

Expected Outputs:

1. List of inconsistencies found across documents
2. List of outdated information that needs updating
3. Recommendations for consolidation or removal
4. Priority updates that should be made immediately
5. Updated documents (if you approve changes)

Would you like me to proceed with this plan? I'll work through each file
systematically and provide a summary report at the end.

Todos
☐ Read and analyze all files in .claude/ directory
☐ Review CLAUDE.md for outdated instructions and consistency
☐ Review README.md for accuracy and completeness
☐ Review start.txt for relevance and accuracy
☐ Check scripts/ directory for any automation needs
☐ Identify inconsistencies and outdated information
☐ Create summary report of findings and recommendations