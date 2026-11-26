---
name: risk-scoring
description: Use when writing or changing alert risk scores or risk levels for any module.
---
One pure function in backend/app/core/scoring.py. Points: exact brand in domain +40, typo similarity >80% +25, MX +15, HTTPS +10, login/payment keywords +20, official logo +30, social image match +20, publisher mismatch +25. Cap at 100. Levels: 0-29 Low, 30-59 Medium, 60-79 High, 80+ Critical. Every rule needs a unit test, including boundaries (29/30, 59/60, 79/80) and the cap.
