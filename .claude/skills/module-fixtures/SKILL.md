---
name: module-fixtures
description: Use when finishing any detection module, to prove its acceptance criterion with a test.
---
Each module needs a fixture in fixtures/ and a pytest that runs the detection against it and asserts an alert is created with evidence and a timestamp. Criteria: typosquat variants, MX stored, live domain screenshot+score, simulated fake APK, Play listing by keyword, simulated fake social account, indexed doc with brand keyword, logo on test site, dashboard shows alerts, analyst can change status.
