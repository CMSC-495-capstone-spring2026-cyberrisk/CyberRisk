# CyberRisk Monitor – Desktop UI Test Plan

## Environment
- OS: Windows
- UI Framework: Tkinter
- Mode: Offline (no backend integration)

## Smoke Tests
- [x] Application launches successfully
- [x] Window title displays "CyberRisk Monitor"
- [x] Application closes cleanly

## Header
- [x] Title is visible
- [x] Last Analysis timestamp is displayed
- [x] Export button renders (placeholder)
- [x] Refresh button renders (placeholder)

## Risk Summary
- [x] Low count displays correctly
- [x] Medium count displays correctly
- [x] High count displays correctly
- [x] Critical count displays correctly
- [x] Overall Risk Score displays

## Alerts Table
- [x] Alerts render in table
- [x] Scrollbar functions correctly
- [x] Severity filter dropdown updates table:
  - [x] All
  - [x] Low
  - [x] Medium
  - [x] High
  - [x] Critical

## Notes
- Backend integration intentionally deferred
- Data currently mock-only for UI validation
