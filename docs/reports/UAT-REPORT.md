# Test / UAT Report — Beyond Cloud Brand Intelligence Platform

- **Generated:** 2026-10-12 05:32 UTC from automated test results of 2026-10-12 05:32 UTC
- **Code version:** `unknown`
- **Automated tests:** 295 passed, 0 failed, 0 skipped (295 total)
- **Requirements:** 183 of 195 satisfied — 162 passed by automated tests, 16 verified by artefact, 5 out of scope; 0 deferred by decision, 0 failing, 12 open

How to reproduce: start the infrastructure (`docs/guides/DEPLOYMENT.md`), then in `backend/` run `python -m uv run pytest` and `python -m uv run python -m scripts.uat_report`. Requirement IDs come from `docs/requirements/01-requirements-register.md`; decisions (D-xx) from `docs/decisions/DECISION-LOG.md`.

## 1. Minimum acceptance criteria (§9)

| ID | Criterion | Result | Proven by |
|---|---|---|---|
| AC-01 | Typosquat: detects generated variants for configured brand | ✅ PASS | test_ac01_typosquat_variants_detected |
| AC-02 | MX: resolves and stores MX records | ✅ PASS | test_ac02_mx_records_resolved_and_stored |
| AC-03 | Active phishing: screenshot + risk score for live suspicious domain | ✅ PASS | test_ac03_live_phishing_domain_screenshot_and_score |
| AC-04 | Fake APK: detects at least one simulated fake APK entry | ✅ PASS | test_ac04_simulated_fake_apk_detected |
| AC-05 | Rogue app: detects unauthorized listing by keyword | ✅ PASS | test_ac05_unauthorized_play_listing_by_keyword |
| AC-06 | Social: detects simulated fake social account | ✅ PASS | test_ac06_simulated_fake_social_account |
| AC-07 | Documents: detects indexed document containing brand keyword | ✅ PASS | test_ac07_indexed_document_with_brand_keyword |
| AC-08 | Logo: detects official logo on a test website | ✅ PASS | test_ac08_official_logo_on_test_website |
| AC-09 | Dashboard displays alerts from all modules | ✅ PASS | test_ac09_alerts_exist_for_all_modules, test_alert_queue_filters_and_search |
| AC-10 | Analyst can change alert status | ✅ PASS | test_ac10_analyst_changes_alert_status |

## 2. Every requirement

### A. Platform objectives (§1, §11)

| ID | Requirement | Result | Evidence |
|---|---|---|---|
| OBJ-01 | Continuously discover and monitor suspicious domains related to client brands | ✅ PASS | test_ac01_typosquat_variants_detected |
| OBJ-02 | Detect phishing infrastructure and active phishing campaigns | ✅ PASS | test_ac03_live_phishing_domain_screenshot_and_score |
| OBJ-03 | Identify fake or unauthorized mobile applications | ✅ PASS | test_ac04_simulated_fake_apk_detected |
| OBJ-04 | Monitor social platforms for impersonation accounts and fraudulent activity | ✅ PASS | test_ac06_simulated_fake_social_account |
| OBJ-05 | Detect exposure of sensitive documents related to monitored brands | ✅ PASS | test_ac07_indexed_document_with_brand_keyword |
| OBJ-06 | Identify unauthorized use of brand logos across websites | ✅ PASS | test_ac08_official_logo_on_test_website |
| OBJ-07 | Generate alerts, dashboards and evidence for analyst review | ✅ PASS | test_ac09_alerts_exist_for_all_modules |
| OBJ-08 | Production-ready for internal analyst use at end of Phase 1 | ✅ VERIFIED | Production-ready: deployment guide, secrets checks, health checks — `docs/guides/DEPLOYMENT.md` |
| OUT-01 | Analyst can add a new brand with official assets | ✅ PASS | test_brand_onboarding_with_logo_and_allowlists |
| OUT-02 | Analyst can prioritize incidents with a consistent risk scoring model | ✅ PASS | test_cap_boundaries_do_not_raise_low_scores, test_cap_reason_reported_in_alert_signals, test_clamped_score_stays_consistent_with_level, test_domain_without_website_is_not_capped, test_each_rule_adds_its_points[signals0-40-brand_exact_in_domain], test_each_rule_adds_its_points[signals1-25-typo_similarity_gt_80], test_each_rule_adds_its_points[signals10-30-doc_sensitive_pattern], test_each_rule_adds_its_points[signals11-20-doc_many_emails], test_each_rule_adds_its_points[signals2-15-mx_present], test_each_rule_adds_its_points[signals3-10-https], test_each_rule_adds_its_points[signals4-20-login_payment_keywords], test_each_rule_adds_its_points[signals5-30-official_logo], test_each_rule_adds_its_points[signals6-20-social_image_match], test_each_rule_adds_its_points[signals7-25-publisher_mismatch], test_each_rule_adds_its_points[signals8-30-doc_brand_keyword], test_each_rule_adds_its_points[signals9-20-doc_official_domain], test_level_boundaries[0-Low], test_level_boundaries[100-Critical], test_level_boundaries[29-Low], test_level_boundaries[30-Medium], test_level_boundaries[59-Medium], test_level_boundaries[60-High], test_level_boundaries[79-High], test_level_boundaries[80-Critical], test_live_site_with_brand_evidence_can_be_critical, test_live_site_without_brand_evidence_capped_at_medium, test_module_level_clamp[apk-raw_points_signals0-Medium], test_module_level_clamp[apk-raw_points_signals1-High], test_module_level_clamp[documents-raw_points_signals6-Medium], test_module_level_clamp[documents-raw_points_signals7-Critical], test_module_level_clamp[logo-raw_points_signals3-High], test_module_level_clamp[rogue_app-raw_points_signals2-Medium], test_module_level_clamp[social-raw_points_signals4-Low], test_module_level_clamp[social-raw_points_signals5-High], test_module_level_clamp[typosquat-raw_points_signals8-Low], test_no_signals_scores_zero_low, test_parked_page_capped_at_low_even_with_brand_text, test_production_refuses_default_secrets, test_production_refuses_test_website_allowlist, test_rules_stack, test_score_capped_at_100, test_typo_similarity_exactly_80_does_not_score |

### B. Out of scope — must NOT be built in Phase 1 (§2)

| ID | Requirement | Result | Evidence |
|---|---|---|---|
| OOS-01 | Automated takedown filing | ➖ N/A | Out of scope for Phase 1 — confirmed not built |
| OOS-02 | AI-based phishing content classification | ➖ N/A | Out of scope for Phase 1 — confirmed not built |
| OOS-03 | Mobile app reverse engineering (metadata/icon extraction from the manifest only) | ➖ N/A | Out of scope for Phase 1 — confirmed not built |
| OOS-04 | Dark web crawling infrastructure | ➖ N/A | Out of scope for Phase 1 — confirmed not built |
| OOS-05 | Multi-tenant customer portal | ➖ N/A | Out of scope for Phase 1 — confirmed not built |

### C. Phishing / Typosquat monitoring (§3.1) — Priority: Critical

| ID | Requirement | Result | Evidence |
|---|---|---|---|
| TYP-01 | Generate variants by character omission | ✅ PASS | test_ac01_typosquat_variants_detected |
| TYP-02 | Generate variants by character substitution | ✅ PASS | test_ac01_typosquat_variants_detected |
| TYP-03 | Generate variants by transposition | ✅ PASS | test_ac01_typosquat_variants_detected |
| TYP-04 | Generate variants by homoglyphs | ✅ PASS | test_ac01_typosquat_variants_detected |
| TYP-05 | Generate variants by added prefixes/suffixes | ✅ PASS | test_ac01_typosquat_variants_detected |
| TYP-06 | Generate variants by character insertion (dev plan) | ✅ PASS | test_ac01_typosquat_variants_detected |
| TYP-07 | Generate TLD variations (dev plan) | ✅ PASS | test_ac01_typosquat_variants_detected |
| TYP-08 | Support .com, .in, .net, .org, .co and country TLDs | ✅ PASS | test_ac01_typosquat_variants_detected |
| TYP-09 | Monitor newly registered domains against generated variants | ✅ PASS | test_newly_registered_domain_from_certificate_transparency |
| TYP-10 | WHOIS lookup for suspicious domains | ✅ PASS | test_newly_registered_domain_from_certificate_transparency |
| TYP-11 | DNS lookup for suspicious domains | ✅ PASS | test_newly_registered_domain_from_certificate_transparency |
| TYP-12 | Daily discovery of suspicious domains | ✅ PASS | test_ac01_typosquat_variants_detected |
| TYP-13 | Similarity score 0–100 per domain | ✅ PASS | test_brand_terms_in_text, test_domain_label_uses_registered_domain, test_fold_homoglyphs_cyrillic_and_digits, test_idn_decoded, test_newly_registered_domain_from_certificate_transparency, test_similar_names_score_high[z\u0435ntrova-100], test_similar_names_score_high[zentorva-80], test_similar_names_score_high[zentova-85], test_similar_names_score_high[zentr0va-100], test_similar_names_score_high[zentrova-100], test_similar_names_score_high[zentrova-login-100], test_similarity_bounds, test_unrelated_names_score_low |

### D. MX record monitoring (§3.1) — Priority: High

| ID | Requirement | Result | Evidence |
|---|---|---|---|
| MX-01 | Resolve MX records for suspicious domains | ✅ PASS | test_ac02_mx_records_resolved_and_stored |
| MX-02 | Store MX records | ✅ PASS | test_ac02_mx_records_resolved_and_stored |
| MX-03 | Flag domains configured for email delivery (MX Enabled Yes/No) | ✅ PASS | test_ac02_mx_records_resolved_and_stored |
| MX-04 | MX risk tiers: No MX = Low, MX = Medium, MX + active website = High (see CONFLICT-02) | ✅ PASS | test_ac02_mx_records_resolved_and_stored |

### E. Active phishing domain detection (§3.1) — Priority: Critical

| ID | Requirement | Result | Evidence |
|---|---|---|---|
| PHI-01 | Check for active HTTP/HTTPS response (Website Live Yes/No) | ✅ PASS | test_ac03_live_phishing_domain_screenshot_and_score |
| PHI-02 | Capture page title | ✅ PASS | test_ac03_live_phishing_domain_screenshot_and_score |
| PHI-03 | Capture favicon hash | ✅ PASS | test_ac03_live_phishing_domain_screenshot_and_score |
| PHI-04 | Capture screenshot | ✅ PASS | test_ac03_live_phishing_domain_screenshot_and_score |
| PHI-05 | Capture SSL certificate details (SSL Present Yes/No) | ✅ PASS | test_ac03_live_phishing_domain_screenshot_and_score |
| PHI-06 | Compare favicon hash with legitimate brand favicon | ✅ PASS | test_ac03_live_phishing_domain_screenshot_and_score |
| PHI-07 | Detect keywords: login, secure, account, verify, payment, etc. | ✅ PASS | test_ac03_live_phishing_domain_screenshot_and_score |
| PHI-08 | Mark domain "Suspected Phishing" when similarity exceeds threshold (see GAP-01) | ✅ PASS | test_ac03_live_phishing_domain_screenshot_and_score, test_brand_name_on_page_is_brand_evidence, test_link_to_official_site_is_brand_evidence, test_official_email_domain_is_brand_evidence, test_ordinary_shop_mentioning_domains_is_not_parked, test_page_naming_its_own_lookalike_domain_is_not_brand_evidence, test_parked_pages_detected[https://example.com/lander-], test_parked_pages_detected[https://sedo.com/search/details/?domain=x.com-], test_parked_pages_detected[https://www.hugedomains.com/domain_profile.cfm?d=chitmart.com-Get this domain], test_parked_pages_detected[https://x.com/-This domain is for sale! Buy this domain today.], test_parked_pages_detected[https://x.com/-This domain may be for sale], test_short_abbreviation_alone_is_not_brand_evidence, test_unrelated_business_with_login_has_no_brand_evidence, test_unrelated_live_site_is_not_suspected_phishing |
| PHI-09 | Output: Domain, Similarity, MX Enabled, Website Live, SSL Present, Screenshot, Risk Level (L/M/H/C) | ✅ PASS | test_ac03_live_phishing_domain_screenshot_and_score |

### F. Fake APK monitoring (§3.2) — Priority: High

| ID | Requirement | Result | Evidence |
|---|---|---|---|
| APK-01 | Search public APK repositories and indexed APK sources | ✅ PASS | test_ac04_simulated_fake_apk_detected, test_archived_html_is_read_from_the_warc_record, test_find_pages_paced_and_reports, test_slugs_keep_shortest_roots |
| APK-02 | Match package names against official package list | ✅ PASS | test_ac04_simulated_fake_apk_detected, test_repackaged_official_app_detected_by_signature |
| APK-03 | Detect similar app names | ✅ PASS | test_ac04_simulated_fake_apk_detected, test_brand_terms_in_text, test_brand_uses_are_relevant[Chitkart Loans-Instant chit loans], test_brand_uses_are_relevant[Chitkartt-chit fund], test_brand_uses_are_relevant[KCPL Chits Helper-Pay your KCPL chit instalments], test_brand_uses_are_relevant[Kodachadri Chit Fund App-Kodachadri chits members], test_brand_uses_are_relevant[MyKCPL Pay-pay dues], test_domain_label_uses_registered_domain, test_fold_homoglyphs_cyrillic_and_digits, test_idn_decoded, test_similar_names_score_high[z\u0435ntrova-100], test_similar_names_score_high[zentorva-80], test_similar_names_score_high[zentova-85], test_similar_names_score_high[zentr0va-100], test_similar_names_score_high[zentrova-100], test_similar_names_score_high[zentrova-login-100], test_similarity_bounds, test_term_strength, test_unrelated_acronym_collisions_are_not_relevant[KCL - Kerala Cricket League-Official app of the Kerala Cricket League], test_unrelated_acronym_collisions_are_not_relevant[KCPL Service & IOT-Kirloskar KCPL service management], test_unrelated_acronym_collisions_are_not_relevant[Kanawha County Public Library-Kanawha County Public Library app. KCPL card holders], test_unrelated_acronym_collisions_are_not_relevant[MyKPL-Solus UK loyalty app], test_unrelated_acronym_collisions_are_not_relevant[RKCPL-Veenus software ERP], test_unrelated_names_score_low, test_zentrova_demo_brand_unchanged |
| APK-04 | Detect similar package identifiers | ✅ PASS | test_ac04_simulated_fake_apk_detected, test_brand_terms_in_text, test_domain_label_uses_registered_domain, test_fold_homoglyphs_cyrillic_and_digits, test_idn_decoded, test_similar_names_score_high[z\u0435ntrova-100], test_similar_names_score_high[zentorva-80], test_similar_names_score_high[zentova-85], test_similar_names_score_high[zentr0va-100], test_similar_names_score_high[zentrova-100], test_similar_names_score_high[zentrova-login-100], test_similarity_bounds, test_unrelated_names_score_low |
| APK-05 | Detect reused icons/logos | ✅ PASS | test_ac04_simulated_fake_apk_detected |
| APK-06 | Detect suspicious developer names | ✅ PASS | test_ac04_simulated_fake_apk_detected, test_repackaged_official_app_detected_by_signature |
| APK-07 | Extract app name, package name, version, developer, download source, SHA256 (if available) | ✅ PASS | test_ac04_simulated_fake_apk_detected, test_repackaged_official_app_detected_by_signature |
| APK-08 | Output: App Name, Package, Similarity, Source URL, Logo Match, Risk Level (M/H) | ✅ PASS | test_ac04_simulated_fake_apk_detected |
| APK-09 | Fake APK inventory with evidence | ✅ PASS | test_ac04_simulated_fake_apk_detected |

### G. Rogue mobile app monitoring (§3.3) — Priority: High

| ID | Requirement | Result | Evidence |
|---|---|---|---|
| ROG-01 | Monitor Google Play search results for brand keywords | ✅ PASS | test_ac05_unauthorized_play_listing_by_keyword, test_play_details_scam_checks_and_apple_store |
| ROG-02 | Monitor other public app stores (dev plan; see GAP-07) — Apple App Store added 2026-10-12 (D-41); APK stores in D-40 | ✅ PASS | test_play_details_scam_checks_and_apple_store |
| ROG-03 | Compare publisher with approved publisher list | ✅ PASS | test_ac05_unauthorized_play_listing_by_keyword, test_play_details_scam_checks_and_apple_store |
| ROG-04 | Flag apps using brand name, logo or product terminology without authorization | ✅ PASS | test_ac05_unauthorized_play_listing_by_keyword, test_brand_uses_are_relevant[Chitkart Loans-Instant chit loans], test_brand_uses_are_relevant[Chitkartt-chit fund], test_brand_uses_are_relevant[KCPL Chits Helper-Pay your KCPL chit instalments], test_brand_uses_are_relevant[Kodachadri Chit Fund App-Kodachadri chits members], test_brand_uses_are_relevant[MyKCPL Pay-pay dues], test_play_details_scam_checks_and_apple_store, test_term_strength, test_unrelated_acronym_collisions_are_not_relevant[KCL - Kerala Cricket League-Official app of the Kerala Cricket League], test_unrelated_acronym_collisions_are_not_relevant[KCPL Service & IOT-Kirloskar KCPL service management], test_unrelated_acronym_collisions_are_not_relevant[Kanawha County Public Library-Kanawha County Public Library app. KCPL card holders], test_unrelated_acronym_collisions_are_not_relevant[MyKPL-Solus UK loyalty app], test_unrelated_acronym_collisions_are_not_relevant[RKCPL-Veenus software ERP], test_zentrova_demo_brand_unchanged |
| ROG-05 | Track app status changes: new, removed, updated | ✅ PASS | test_ac05_unauthorized_play_listing_by_keyword, test_rogue_app_removed_is_tracked |
| ROG-06 | Output: Store, App Name, Publisher, Official Publisher Match, Install Count, Risk Level (M/H) | ✅ PASS | test_ac05_unauthorized_play_listing_by_keyword |

### H. Social media impersonation (§3.4) — Priority: High

| ID | Requirement | Result | Evidence |
|---|---|---|---|
| SOC-01 | Platform: X (Twitter) | ✅ PASS | test_ac06_simulated_fake_social_account |
| SOC-02 | Platform: Facebook | ✅ PASS | test_ac06_simulated_fake_social_account |
| SOC-03 | Platform: Instagram | ✅ PASS | test_ac06_simulated_fake_social_account |
| SOC-04 | Platform: LinkedIn | ✅ PASS | test_ac06_simulated_fake_social_account |
| SOC-05 | Platform: Telegram public channels/usernames | ✅ PASS | test_ac06_simulated_fake_social_account |
| SOC-06 | Username similarity | ✅ PASS | test_ac06_simulated_fake_social_account, test_brand_terms_in_text, test_brand_uses_are_relevant[Chitkart Loans-Instant chit loans], test_brand_uses_are_relevant[Chitkartt-chit fund], test_brand_uses_are_relevant[KCPL Chits Helper-Pay your KCPL chit instalments], test_brand_uses_are_relevant[Kodachadri Chit Fund App-Kodachadri chits members], test_brand_uses_are_relevant[MyKCPL Pay-pay dues], test_domain_label_uses_registered_domain, test_fold_homoglyphs_cyrillic_and_digits, test_idn_decoded, test_similar_names_score_high[z\u0435ntrova-100], test_similar_names_score_high[zentorva-80], test_similar_names_score_high[zentova-85], test_similar_names_score_high[zentr0va-100], test_similar_names_score_high[zentrova-100], test_similar_names_score_high[zentrova-login-100], test_similarity_bounds, test_term_strength, test_unrelated_acronym_collisions_are_not_relevant[KCL - Kerala Cricket League-Official app of the Kerala Cricket League], test_unrelated_acronym_collisions_are_not_relevant[KCPL Service & IOT-Kirloskar KCPL service management], test_unrelated_acronym_collisions_are_not_relevant[Kanawha County Public Library-Kanawha County Public Library app. KCPL card holders], test_unrelated_acronym_collisions_are_not_relevant[MyKPL-Solus UK loyalty app], test_unrelated_acronym_collisions_are_not_relevant[RKCPL-Veenus software ERP], test_unrelated_names_score_low, test_zentrova_demo_brand_unchanged |
| SOC-07 | Display name similarity | ✅ PASS | test_ac06_simulated_fake_social_account, test_brand_terms_in_text, test_brand_uses_are_relevant[Chitkart Loans-Instant chit loans], test_brand_uses_are_relevant[Chitkartt-chit fund], test_brand_uses_are_relevant[KCPL Chits Helper-Pay your KCPL chit instalments], test_brand_uses_are_relevant[Kodachadri Chit Fund App-Kodachadri chits members], test_brand_uses_are_relevant[MyKCPL Pay-pay dues], test_domain_label_uses_registered_domain, test_fold_homoglyphs_cyrillic_and_digits, test_idn_decoded, test_similar_names_score_high[z\u0435ntrova-100], test_similar_names_score_high[zentorva-80], test_similar_names_score_high[zentova-85], test_similar_names_score_high[zentr0va-100], test_similar_names_score_high[zentrova-100], test_similar_names_score_high[zentrova-login-100], test_similarity_bounds, test_term_strength, test_unrelated_acronym_collisions_are_not_relevant[KCL - Kerala Cricket League-Official app of the Kerala Cricket League], test_unrelated_acronym_collisions_are_not_relevant[KCPL Service & IOT-Kirloskar KCPL service management], test_unrelated_acronym_collisions_are_not_relevant[Kanawha County Public Library-Kanawha County Public Library app. KCPL card holders], test_unrelated_acronym_collisions_are_not_relevant[MyKPL-Solus UK loyalty app], test_unrelated_acronym_collisions_are_not_relevant[RKCPL-Veenus software ERP], test_unrelated_names_score_low, test_zentrova_demo_brand_unchanged |
| SOC-08 | Profile image/logo similarity | ✅ PASS | test_ac06_simulated_fake_social_account |
| SOC-09 | Bio/description contains brand name | ✅ PASS | test_ac06_simulated_fake_social_account |
| SOC-10 | Uses official support/contact terminology | ✅ PASS | test_ac06_simulated_fake_social_account |
| SOC-11 | Output: Platform, Username, Display Name, Similarity, Logo Match, Followers, Risk Level (L/M/H) | ✅ PASS | test_ac06_simulated_fake_social_account |
| SOC-12 | Impersonation dashboard with screenshots (dev plan) | ✅ PASS | test_ac06_simulated_fake_social_account |

### I. Sensitive document monitoring (§3.5) — Priority: Medium

| ID | Requirement | Result | Evidence |
|---|---|---|---|
| DOC-01 | Source: search-engine-indexed documents | ✅ PASS | test_ac07_indexed_document_with_brand_keyword |
| DOC-02 | Source: public file-sharing links | ✅ PASS | test_ac07_indexed_document_with_brand_keyword |
| DOC-03 | Source: exposed PDF/DOC/XLS/PPT accessible without authentication | ✅ PASS | test_ac07_indexed_document_with_brand_keyword |
| DOC-04 | Brand keyword match | ✅ PASS | test_ac07_indexed_document_with_brand_keyword, test_brand_uses_are_relevant[Chitkart Loans-Instant chit loans], test_brand_uses_are_relevant[Chitkartt-chit fund], test_brand_uses_are_relevant[KCPL Chits Helper-Pay your KCPL chit instalments], test_brand_uses_are_relevant[Kodachadri Chit Fund App-Kodachadri chits members], test_brand_uses_are_relevant[MyKCPL Pay-pay dues], test_term_strength, test_unrelated_acronym_collisions_are_not_relevant[KCL - Kerala Cricket League-Official app of the Kerala Cricket League], test_unrelated_acronym_collisions_are_not_relevant[KCPL Service & IOT-Kirloskar KCPL service management], test_unrelated_acronym_collisions_are_not_relevant[Kanawha County Public Library-Kanawha County Public Library app. KCPL card holders], test_unrelated_acronym_collisions_are_not_relevant[MyKPL-Solus UK loyalty app], test_unrelated_acronym_collisions_are_not_relevant[RKCPL-Veenus software ERP], test_zentrova_demo_brand_unchanged |
| DOC-05 | Domain match | ✅ PASS | test_ac07_indexed_document_with_brand_keyword |
| DOC-06 | Email address pattern match | ✅ PASS | test_ac07_indexed_document_with_brand_keyword |
| DOC-07 | Filename pattern analysis (confidential, internal, salary, customer, …) | ✅ PASS | test_ac07_indexed_document_with_brand_keyword |
| DOC-08 | Output: Document Name, File Type, URL, Brand Match, Exposure Confidence (L/M/H), Risk Level (M/H/C) | ✅ PASS | test_ac07_indexed_document_with_brand_keyword |

### J. Brand logo on websites (§3.6) — Priority: Medium

| ID | Requirement | Result | Evidence |
|---|---|---|---|
| LOGO-01 | Crawl discovered suspicious domains and websites | ✅ PASS | test_ac08_official_logo_on_test_website, test_follow_up_queued_after_scan, test_logo_alone_runs_immediately, test_logo_follows_domain_scan |
| LOGO-02 | Extract images from pages | ✅ PASS | test_ac08_official_logo_on_test_website |
| LOGO-03 | Compute perceptual hash (pHash) | ✅ PASS | test_ac08_official_logo_on_test_website |
| LOGO-04 | Match against stored official brand logos | ✅ PASS | test_ac08_official_logo_on_test_website |
| LOGO-05 | Capture screenshot evidence when matched | ✅ PASS | test_ac08_official_logo_on_test_website |
| LOGO-06 | Output: Website, Page URL, Logo Match Score 0–100, Screenshot, Risk Level (M/H) | ✅ PASS | test_ac08_official_logo_on_test_website |

### K. Dashboard, workflow, export (§4, dev plan) — Priority: Critical

| ID | Requirement | Result | Evidence |
|---|---|---|---|
| DSH-01 | Executive: total alerts today | ✅ PASS | test_executive_dashboard_numbers |
| DSH-02 | Executive: High/Critical alerts | ✅ PASS | test_executive_dashboard_numbers |
| DSH-03 | Executive: new phishing domains | ✅ PASS | test_executive_dashboard_numbers |
| DSH-04 | Executive: new impersonation accounts | ✅ PASS | test_executive_dashboard_numbers |
| DSH-05 | Executive: new rogue apps | ✅ PASS | test_executive_dashboard_numbers |
| DSH-06 | Executive: sensitive document exposures | ✅ PASS | test_executive_dashboard_numbers |
| DSH-07 | Analyst: alert queue | ✅ PASS | test_alert_queue_filters_and_search |
| DSH-08 | Analyst: evidence screenshots | ✅ PASS | test_alert_detail_has_scoring_explanation |
| DSH-09 | Analyst: risk score | ✅ PASS | test_alert_queue_filters_and_search |
| DSH-10 | Status tracking: New, Under Review, Confirmed, False Positive, Closed (see CONFLICT-03) | ✅ PASS | test_ac10_analyst_changes_alert_status, test_false_positive_path |
| DSH-11 | Filter: brand name | ✅ PASS | test_alert_queue_filters_and_search |
| DSH-12 | Filter: module type | ✅ PASS | test_alert_queue_filters_and_search |
| DSH-13 | Filter: risk level | ✅ PASS | test_alert_queue_filters_and_search |
| DSH-14 | Filter: date range | ✅ PASS | test_alert_queue_filters_and_search |
| DSH-15 | Filter: status | ✅ PASS | test_alert_queue_filters_and_search |
| DSH-16 | Search | ✅ PASS | test_alert_queue_filters_and_search |
| DSH-17 | Dashboard charts | ✅ PASS | test_executive_dashboard_numbers |
| DSH-18 | Export CSV | ✅ PASS | test_csv_export_matches_filters |
| DSH-19 | Export PDF | ✅ PASS | test_pdf_export_html_renders_all_rows |
| DSH-20 | Responsive layout | ✅ VERIFIED | Responsive layout (phone/tablet screenshots in the demo guide) — `docs/demo/DEMO-GUIDE.md` |
| DSH-21 | Displays alerts from all modules | ✅ PASS | test_ac09_alerts_exist_for_all_modules, test_alert_queue_filters_and_search |

### L. Risk scoring (§6)

| ID | Requirement | Result | Evidence |
|---|---|---|---|
| RSK-01 | Brand exact match in domain +40 | ✅ PASS | test_cap_boundaries_do_not_raise_low_scores, test_cap_reason_reported_in_alert_signals, test_clamped_score_stays_consistent_with_level, test_domain_without_website_is_not_capped, test_each_rule_adds_its_points[signals0-40-brand_exact_in_domain], test_each_rule_adds_its_points[signals1-25-typo_similarity_gt_80], test_each_rule_adds_its_points[signals10-30-doc_sensitive_pattern], test_each_rule_adds_its_points[signals11-20-doc_many_emails], test_each_rule_adds_its_points[signals2-15-mx_present], test_each_rule_adds_its_points[signals3-10-https], test_each_rule_adds_its_points[signals4-20-login_payment_keywords], test_each_rule_adds_its_points[signals5-30-official_logo], test_each_rule_adds_its_points[signals6-20-social_image_match], test_each_rule_adds_its_points[signals7-25-publisher_mismatch], test_each_rule_adds_its_points[signals8-30-doc_brand_keyword], test_each_rule_adds_its_points[signals9-20-doc_official_domain], test_level_boundaries[0-Low], test_level_boundaries[100-Critical], test_level_boundaries[29-Low], test_level_boundaries[30-Medium], test_level_boundaries[59-Medium], test_level_boundaries[60-High], test_level_boundaries[79-High], test_level_boundaries[80-Critical], test_live_site_with_brand_evidence_can_be_critical, test_live_site_without_brand_evidence_capped_at_medium, test_module_level_clamp[apk-raw_points_signals0-Medium], test_module_level_clamp[apk-raw_points_signals1-High], test_module_level_clamp[documents-raw_points_signals6-Medium], test_module_level_clamp[documents-raw_points_signals7-Critical], test_module_level_clamp[logo-raw_points_signals3-High], test_module_level_clamp[rogue_app-raw_points_signals2-Medium], test_module_level_clamp[social-raw_points_signals4-Low], test_module_level_clamp[social-raw_points_signals5-High], test_module_level_clamp[typosquat-raw_points_signals8-Low], test_no_signals_scores_zero_low, test_parked_page_capped_at_low_even_with_brand_text, test_production_refuses_default_secrets, test_production_refuses_test_website_allowlist, test_rules_stack, test_score_capped_at_100, test_typo_similarity_exactly_80_does_not_score |
| RSK-02 | Typosquat similarity > 80% +25 | ✅ PASS | test_cap_boundaries_do_not_raise_low_scores, test_cap_reason_reported_in_alert_signals, test_clamped_score_stays_consistent_with_level, test_domain_without_website_is_not_capped, test_each_rule_adds_its_points[signals0-40-brand_exact_in_domain], test_each_rule_adds_its_points[signals1-25-typo_similarity_gt_80], test_each_rule_adds_its_points[signals10-30-doc_sensitive_pattern], test_each_rule_adds_its_points[signals11-20-doc_many_emails], test_each_rule_adds_its_points[signals2-15-mx_present], test_each_rule_adds_its_points[signals3-10-https], test_each_rule_adds_its_points[signals4-20-login_payment_keywords], test_each_rule_adds_its_points[signals5-30-official_logo], test_each_rule_adds_its_points[signals6-20-social_image_match], test_each_rule_adds_its_points[signals7-25-publisher_mismatch], test_each_rule_adds_its_points[signals8-30-doc_brand_keyword], test_each_rule_adds_its_points[signals9-20-doc_official_domain], test_level_boundaries[0-Low], test_level_boundaries[100-Critical], test_level_boundaries[29-Low], test_level_boundaries[30-Medium], test_level_boundaries[59-Medium], test_level_boundaries[60-High], test_level_boundaries[79-High], test_level_boundaries[80-Critical], test_live_site_with_brand_evidence_can_be_critical, test_live_site_without_brand_evidence_capped_at_medium, test_module_level_clamp[apk-raw_points_signals0-Medium], test_module_level_clamp[apk-raw_points_signals1-High], test_module_level_clamp[documents-raw_points_signals6-Medium], test_module_level_clamp[documents-raw_points_signals7-Critical], test_module_level_clamp[logo-raw_points_signals3-High], test_module_level_clamp[rogue_app-raw_points_signals2-Medium], test_module_level_clamp[social-raw_points_signals4-Low], test_module_level_clamp[social-raw_points_signals5-High], test_module_level_clamp[typosquat-raw_points_signals8-Low], test_no_signals_scores_zero_low, test_parked_page_capped_at_low_even_with_brand_text, test_production_refuses_default_secrets, test_production_refuses_test_website_allowlist, test_rules_stack, test_score_capped_at_100, test_typo_similarity_exactly_80_does_not_score |
| RSK-03 | MX present +15 | ✅ PASS | test_cap_boundaries_do_not_raise_low_scores, test_cap_reason_reported_in_alert_signals, test_clamped_score_stays_consistent_with_level, test_domain_without_website_is_not_capped, test_each_rule_adds_its_points[signals0-40-brand_exact_in_domain], test_each_rule_adds_its_points[signals1-25-typo_similarity_gt_80], test_each_rule_adds_its_points[signals10-30-doc_sensitive_pattern], test_each_rule_adds_its_points[signals11-20-doc_many_emails], test_each_rule_adds_its_points[signals2-15-mx_present], test_each_rule_adds_its_points[signals3-10-https], test_each_rule_adds_its_points[signals4-20-login_payment_keywords], test_each_rule_adds_its_points[signals5-30-official_logo], test_each_rule_adds_its_points[signals6-20-social_image_match], test_each_rule_adds_its_points[signals7-25-publisher_mismatch], test_each_rule_adds_its_points[signals8-30-doc_brand_keyword], test_each_rule_adds_its_points[signals9-20-doc_official_domain], test_level_boundaries[0-Low], test_level_boundaries[100-Critical], test_level_boundaries[29-Low], test_level_boundaries[30-Medium], test_level_boundaries[59-Medium], test_level_boundaries[60-High], test_level_boundaries[79-High], test_level_boundaries[80-Critical], test_live_site_with_brand_evidence_can_be_critical, test_live_site_without_brand_evidence_capped_at_medium, test_module_level_clamp[apk-raw_points_signals0-Medium], test_module_level_clamp[apk-raw_points_signals1-High], test_module_level_clamp[documents-raw_points_signals6-Medium], test_module_level_clamp[documents-raw_points_signals7-Critical], test_module_level_clamp[logo-raw_points_signals3-High], test_module_level_clamp[rogue_app-raw_points_signals2-Medium], test_module_level_clamp[social-raw_points_signals4-Low], test_module_level_clamp[social-raw_points_signals5-High], test_module_level_clamp[typosquat-raw_points_signals8-Low], test_no_signals_scores_zero_low, test_parked_page_capped_at_low_even_with_brand_text, test_production_refuses_default_secrets, test_production_refuses_test_website_allowlist, test_rules_stack, test_score_capped_at_100, test_typo_similarity_exactly_80_does_not_score |
| RSK-04 | HTTPS enabled +10 | ✅ PASS | test_cap_boundaries_do_not_raise_low_scores, test_cap_reason_reported_in_alert_signals, test_clamped_score_stays_consistent_with_level, test_domain_without_website_is_not_capped, test_each_rule_adds_its_points[signals0-40-brand_exact_in_domain], test_each_rule_adds_its_points[signals1-25-typo_similarity_gt_80], test_each_rule_adds_its_points[signals10-30-doc_sensitive_pattern], test_each_rule_adds_its_points[signals11-20-doc_many_emails], test_each_rule_adds_its_points[signals2-15-mx_present], test_each_rule_adds_its_points[signals3-10-https], test_each_rule_adds_its_points[signals4-20-login_payment_keywords], test_each_rule_adds_its_points[signals5-30-official_logo], test_each_rule_adds_its_points[signals6-20-social_image_match], test_each_rule_adds_its_points[signals7-25-publisher_mismatch], test_each_rule_adds_its_points[signals8-30-doc_brand_keyword], test_each_rule_adds_its_points[signals9-20-doc_official_domain], test_level_boundaries[0-Low], test_level_boundaries[100-Critical], test_level_boundaries[29-Low], test_level_boundaries[30-Medium], test_level_boundaries[59-Medium], test_level_boundaries[60-High], test_level_boundaries[79-High], test_level_boundaries[80-Critical], test_live_site_with_brand_evidence_can_be_critical, test_live_site_without_brand_evidence_capped_at_medium, test_module_level_clamp[apk-raw_points_signals0-Medium], test_module_level_clamp[apk-raw_points_signals1-High], test_module_level_clamp[documents-raw_points_signals6-Medium], test_module_level_clamp[documents-raw_points_signals7-Critical], test_module_level_clamp[logo-raw_points_signals3-High], test_module_level_clamp[rogue_app-raw_points_signals2-Medium], test_module_level_clamp[social-raw_points_signals4-Low], test_module_level_clamp[social-raw_points_signals5-High], test_module_level_clamp[typosquat-raw_points_signals8-Low], test_no_signals_scores_zero_low, test_parked_page_capped_at_low_even_with_brand_text, test_production_refuses_default_secrets, test_production_refuses_test_website_allowlist, test_rules_stack, test_score_capped_at_100, test_typo_similarity_exactly_80_does_not_score |
| RSK-05 | Login/payment keywords +20 | ✅ PASS | test_cap_boundaries_do_not_raise_low_scores, test_cap_reason_reported_in_alert_signals, test_clamped_score_stays_consistent_with_level, test_domain_without_website_is_not_capped, test_each_rule_adds_its_points[signals0-40-brand_exact_in_domain], test_each_rule_adds_its_points[signals1-25-typo_similarity_gt_80], test_each_rule_adds_its_points[signals10-30-doc_sensitive_pattern], test_each_rule_adds_its_points[signals11-20-doc_many_emails], test_each_rule_adds_its_points[signals2-15-mx_present], test_each_rule_adds_its_points[signals3-10-https], test_each_rule_adds_its_points[signals4-20-login_payment_keywords], test_each_rule_adds_its_points[signals5-30-official_logo], test_each_rule_adds_its_points[signals6-20-social_image_match], test_each_rule_adds_its_points[signals7-25-publisher_mismatch], test_each_rule_adds_its_points[signals8-30-doc_brand_keyword], test_each_rule_adds_its_points[signals9-20-doc_official_domain], test_level_boundaries[0-Low], test_level_boundaries[100-Critical], test_level_boundaries[29-Low], test_level_boundaries[30-Medium], test_level_boundaries[59-Medium], test_level_boundaries[60-High], test_level_boundaries[79-High], test_level_boundaries[80-Critical], test_live_site_with_brand_evidence_can_be_critical, test_live_site_without_brand_evidence_capped_at_medium, test_module_level_clamp[apk-raw_points_signals0-Medium], test_module_level_clamp[apk-raw_points_signals1-High], test_module_level_clamp[documents-raw_points_signals6-Medium], test_module_level_clamp[documents-raw_points_signals7-Critical], test_module_level_clamp[logo-raw_points_signals3-High], test_module_level_clamp[rogue_app-raw_points_signals2-Medium], test_module_level_clamp[social-raw_points_signals4-Low], test_module_level_clamp[social-raw_points_signals5-High], test_module_level_clamp[typosquat-raw_points_signals8-Low], test_no_signals_scores_zero_low, test_parked_page_capped_at_low_even_with_brand_text, test_production_refuses_default_secrets, test_production_refuses_test_website_allowlist, test_rules_stack, test_score_capped_at_100, test_typo_similarity_exactly_80_does_not_score |
| RSK-06 | Official logo detected +30 | ✅ PASS | test_cap_boundaries_do_not_raise_low_scores, test_cap_reason_reported_in_alert_signals, test_clamped_score_stays_consistent_with_level, test_domain_without_website_is_not_capped, test_each_rule_adds_its_points[signals0-40-brand_exact_in_domain], test_each_rule_adds_its_points[signals1-25-typo_similarity_gt_80], test_each_rule_adds_its_points[signals10-30-doc_sensitive_pattern], test_each_rule_adds_its_points[signals11-20-doc_many_emails], test_each_rule_adds_its_points[signals2-15-mx_present], test_each_rule_adds_its_points[signals3-10-https], test_each_rule_adds_its_points[signals4-20-login_payment_keywords], test_each_rule_adds_its_points[signals5-30-official_logo], test_each_rule_adds_its_points[signals6-20-social_image_match], test_each_rule_adds_its_points[signals7-25-publisher_mismatch], test_each_rule_adds_its_points[signals8-30-doc_brand_keyword], test_each_rule_adds_its_points[signals9-20-doc_official_domain], test_level_boundaries[0-Low], test_level_boundaries[100-Critical], test_level_boundaries[29-Low], test_level_boundaries[30-Medium], test_level_boundaries[59-Medium], test_level_boundaries[60-High], test_level_boundaries[79-High], test_level_boundaries[80-Critical], test_live_site_with_brand_evidence_can_be_critical, test_live_site_without_brand_evidence_capped_at_medium, test_module_level_clamp[apk-raw_points_signals0-Medium], test_module_level_clamp[apk-raw_points_signals1-High], test_module_level_clamp[documents-raw_points_signals6-Medium], test_module_level_clamp[documents-raw_points_signals7-Critical], test_module_level_clamp[logo-raw_points_signals3-High], test_module_level_clamp[rogue_app-raw_points_signals2-Medium], test_module_level_clamp[social-raw_points_signals4-Low], test_module_level_clamp[social-raw_points_signals5-High], test_module_level_clamp[typosquat-raw_points_signals8-Low], test_no_signals_scores_zero_low, test_parked_page_capped_at_low_even_with_brand_text, test_production_refuses_default_secrets, test_production_refuses_test_website_allowlist, test_rules_stack, test_score_capped_at_100, test_typo_similarity_exactly_80_does_not_score |
| RSK-07 | Social profile image matches logo +20 | ✅ PASS | test_cap_boundaries_do_not_raise_low_scores, test_cap_reason_reported_in_alert_signals, test_clamped_score_stays_consistent_with_level, test_domain_without_website_is_not_capped, test_each_rule_adds_its_points[signals0-40-brand_exact_in_domain], test_each_rule_adds_its_points[signals1-25-typo_similarity_gt_80], test_each_rule_adds_its_points[signals10-30-doc_sensitive_pattern], test_each_rule_adds_its_points[signals11-20-doc_many_emails], test_each_rule_adds_its_points[signals2-15-mx_present], test_each_rule_adds_its_points[signals3-10-https], test_each_rule_adds_its_points[signals4-20-login_payment_keywords], test_each_rule_adds_its_points[signals5-30-official_logo], test_each_rule_adds_its_points[signals6-20-social_image_match], test_each_rule_adds_its_points[signals7-25-publisher_mismatch], test_each_rule_adds_its_points[signals8-30-doc_brand_keyword], test_each_rule_adds_its_points[signals9-20-doc_official_domain], test_level_boundaries[0-Low], test_level_boundaries[100-Critical], test_level_boundaries[29-Low], test_level_boundaries[30-Medium], test_level_boundaries[59-Medium], test_level_boundaries[60-High], test_level_boundaries[79-High], test_level_boundaries[80-Critical], test_live_site_with_brand_evidence_can_be_critical, test_live_site_without_brand_evidence_capped_at_medium, test_module_level_clamp[apk-raw_points_signals0-Medium], test_module_level_clamp[apk-raw_points_signals1-High], test_module_level_clamp[documents-raw_points_signals6-Medium], test_module_level_clamp[documents-raw_points_signals7-Critical], test_module_level_clamp[logo-raw_points_signals3-High], test_module_level_clamp[rogue_app-raw_points_signals2-Medium], test_module_level_clamp[social-raw_points_signals4-Low], test_module_level_clamp[social-raw_points_signals5-High], test_module_level_clamp[typosquat-raw_points_signals8-Low], test_no_signals_scores_zero_low, test_parked_page_capped_at_low_even_with_brand_text, test_production_refuses_default_secrets, test_production_refuses_test_website_allowlist, test_rules_stack, test_score_capped_at_100, test_typo_similarity_exactly_80_does_not_score |
| RSK-08 | Official publisher mismatch +25 | ✅ PASS | test_cap_boundaries_do_not_raise_low_scores, test_cap_reason_reported_in_alert_signals, test_clamped_score_stays_consistent_with_level, test_domain_without_website_is_not_capped, test_each_rule_adds_its_points[signals0-40-brand_exact_in_domain], test_each_rule_adds_its_points[signals1-25-typo_similarity_gt_80], test_each_rule_adds_its_points[signals10-30-doc_sensitive_pattern], test_each_rule_adds_its_points[signals11-20-doc_many_emails], test_each_rule_adds_its_points[signals2-15-mx_present], test_each_rule_adds_its_points[signals3-10-https], test_each_rule_adds_its_points[signals4-20-login_payment_keywords], test_each_rule_adds_its_points[signals5-30-official_logo], test_each_rule_adds_its_points[signals6-20-social_image_match], test_each_rule_adds_its_points[signals7-25-publisher_mismatch], test_each_rule_adds_its_points[signals8-30-doc_brand_keyword], test_each_rule_adds_its_points[signals9-20-doc_official_domain], test_level_boundaries[0-Low], test_level_boundaries[100-Critical], test_level_boundaries[29-Low], test_level_boundaries[30-Medium], test_level_boundaries[59-Medium], test_level_boundaries[60-High], test_level_boundaries[79-High], test_level_boundaries[80-Critical], test_live_site_with_brand_evidence_can_be_critical, test_live_site_without_brand_evidence_capped_at_medium, test_module_level_clamp[apk-raw_points_signals0-Medium], test_module_level_clamp[apk-raw_points_signals1-High], test_module_level_clamp[documents-raw_points_signals6-Medium], test_module_level_clamp[documents-raw_points_signals7-Critical], test_module_level_clamp[logo-raw_points_signals3-High], test_module_level_clamp[rogue_app-raw_points_signals2-Medium], test_module_level_clamp[social-raw_points_signals4-Low], test_module_level_clamp[social-raw_points_signals5-High], test_module_level_clamp[typosquat-raw_points_signals8-Low], test_no_signals_scores_zero_low, test_parked_page_capped_at_low_even_with_brand_text, test_production_refuses_default_secrets, test_production_refuses_test_website_allowlist, test_rules_stack, test_score_capped_at_100, test_typo_similarity_exactly_80_does_not_score |
| RSK-09 | Levels: 0–29 Low, 30–59 Medium, 60–79 High, 80+ Critical | ✅ PASS | test_cap_boundaries_do_not_raise_low_scores, test_cap_reason_reported_in_alert_signals, test_clamped_score_stays_consistent_with_level, test_domain_without_website_is_not_capped, test_each_rule_adds_its_points[signals0-40-brand_exact_in_domain], test_each_rule_adds_its_points[signals1-25-typo_similarity_gt_80], test_each_rule_adds_its_points[signals10-30-doc_sensitive_pattern], test_each_rule_adds_its_points[signals11-20-doc_many_emails], test_each_rule_adds_its_points[signals2-15-mx_present], test_each_rule_adds_its_points[signals3-10-https], test_each_rule_adds_its_points[signals4-20-login_payment_keywords], test_each_rule_adds_its_points[signals5-30-official_logo], test_each_rule_adds_its_points[signals6-20-social_image_match], test_each_rule_adds_its_points[signals7-25-publisher_mismatch], test_each_rule_adds_its_points[signals8-30-doc_brand_keyword], test_each_rule_adds_its_points[signals9-20-doc_official_domain], test_level_boundaries[0-Low], test_level_boundaries[100-Critical], test_level_boundaries[29-Low], test_level_boundaries[30-Medium], test_level_boundaries[59-Medium], test_level_boundaries[60-High], test_level_boundaries[79-High], test_level_boundaries[80-Critical], test_live_site_with_brand_evidence_can_be_critical, test_live_site_without_brand_evidence_capped_at_medium, test_module_level_clamp[apk-raw_points_signals0-Medium], test_module_level_clamp[apk-raw_points_signals1-High], test_module_level_clamp[documents-raw_points_signals6-Medium], test_module_level_clamp[documents-raw_points_signals7-Critical], test_module_level_clamp[logo-raw_points_signals3-High], test_module_level_clamp[rogue_app-raw_points_signals2-Medium], test_module_level_clamp[social-raw_points_signals4-Low], test_module_level_clamp[social-raw_points_signals5-High], test_module_level_clamp[typosquat-raw_points_signals8-Low], test_no_signals_scores_zero_low, test_parked_lookalike_scores_low, test_parked_page_capped_at_low_even_with_brand_text, test_production_refuses_default_secrets, test_production_refuses_test_website_allowlist, test_rules_stack, test_score_capped_at_100, test_typo_similarity_exactly_80_does_not_score, test_unrelated_live_site_capped_at_medium |
| RSK-10 | Score capped at 100 (0–100 scales used throughout) | ✅ PASS | test_cap_boundaries_do_not_raise_low_scores, test_cap_reason_reported_in_alert_signals, test_clamped_score_stays_consistent_with_level, test_domain_without_website_is_not_capped, test_each_rule_adds_its_points[signals0-40-brand_exact_in_domain], test_each_rule_adds_its_points[signals1-25-typo_similarity_gt_80], test_each_rule_adds_its_points[signals10-30-doc_sensitive_pattern], test_each_rule_adds_its_points[signals11-20-doc_many_emails], test_each_rule_adds_its_points[signals2-15-mx_present], test_each_rule_adds_its_points[signals3-10-https], test_each_rule_adds_its_points[signals4-20-login_payment_keywords], test_each_rule_adds_its_points[signals5-30-official_logo], test_each_rule_adds_its_points[signals6-20-social_image_match], test_each_rule_adds_its_points[signals7-25-publisher_mismatch], test_each_rule_adds_its_points[signals8-30-doc_brand_keyword], test_each_rule_adds_its_points[signals9-20-doc_official_domain], test_level_boundaries[0-Low], test_level_boundaries[100-Critical], test_level_boundaries[29-Low], test_level_boundaries[30-Medium], test_level_boundaries[59-Medium], test_level_boundaries[60-High], test_level_boundaries[79-High], test_level_boundaries[80-Critical], test_live_site_with_brand_evidence_can_be_critical, test_live_site_without_brand_evidence_capped_at_medium, test_module_level_clamp[apk-raw_points_signals0-Medium], test_module_level_clamp[apk-raw_points_signals1-High], test_module_level_clamp[documents-raw_points_signals6-Medium], test_module_level_clamp[documents-raw_points_signals7-Critical], test_module_level_clamp[logo-raw_points_signals3-High], test_module_level_clamp[rogue_app-raw_points_signals2-Medium], test_module_level_clamp[social-raw_points_signals4-Low], test_module_level_clamp[social-raw_points_signals5-High], test_module_level_clamp[typosquat-raw_points_signals8-Low], test_no_signals_scores_zero_low, test_parked_page_capped_at_low_even_with_brand_text, test_production_refuses_default_secrets, test_production_refuses_test_website_allowlist, test_rules_stack, test_score_capped_at_100, test_typo_similarity_exactly_80_does_not_score |

### M. Foundation & platform (§5, §7, §8)

| ID | Requirement | Result | Evidence |
|---|---|---|---|
| FND-01 | Repository setup | ✅ VERIFIED | Repository with backend, frontend, deploy, docs, fixtures — `backend/pyproject.toml` |
| FND-02 | Database schema finalized + migrations | ✅ VERIFIED | Alembic migrations create the schema (used by every integration test run) — `backend/app/alembic/versions` |
| FND-03 | Authentication for internal analysts | ✅ PASS | test_admin_manages_users, test_analyst_cannot_administer, test_login_and_protected_routes |
| FND-04 | Brand configuration module (onboarding) | ✅ PASS | test_brand_onboarding_with_logo_and_allowlists |
| FND-05 | Official logo upload | ✅ PASS | test_brand_onboarding_with_logo_and_allowlists |
| FND-06 | Whitelists: official domains, packages, publishers | ✅ PASS | test_brand_onboarding_with_logo_and_allowlists, test_normalize[domain-chitkart.com-chitkart.com], test_normalize[domain-https://www.MyKCPL.com/login-mykcpl.com], test_normalize[email_domain-support@mykcpl.com-mykcpl.com], test_normalize[package-com.Zentrova.Mobile-com.zentrova.mobile], test_normalize[package-https://play.google.com/store/apps/details?id=com.bharatchits.androidapp&hl=en-com.bharatchits.androidapp], test_normalize[publisher- Kodachadri Fintech Pvt Ltd -Kodachadri Fintech Pvt Ltd], test_normalize[social_handle-@ZentrovaBank-zentrovabank], test_normalize[social_handle-https://t.me/zentrova_news-zentrova_news], test_normalize[social_handle-https://www.facebook.com/kodachadrichitsofficial/-kodachadrichitsofficial], test_normalize[social_handle-https://www.instagram.com/chit_kart/-chit_kart], test_normalize[social_handle-https://www.instagram.com/kodachadrichits/-kodachadrichits], test_normalize[social_handle-https://www.linkedin.com/company/chitkart/?original_referer=-chitkart], test_normalize[social_handle-https://www.linkedin.com/company/kodachadrichits/-kodachadrichits], test_normalize[social_handle-https://www.youtube.com/@kodachadrichitsofficial-kodachadrichitsofficial], test_normalize[social_handle-https://x.com/ZentrovaBank-zentrovabank], test_normalize[social_handle-instagram.com/zentrova/-zentrova], test_normalize[social_handle-zentrova_official-zentrova_official], test_signing_cert_fingerprint_formats[89:D3:8A:FD:9B:E5:0A:DF:18:33:62:8E:82:5A:05:86:9C:CD:B2:D8:52:54:CD:F0:72:09:CA:E1:4B:11:5E:FC], test_signing_cert_fingerprint_formats[89d38afd 9be50adf 1833628e 825a0586 9ccdb2d8 5254cdf0 7209cae1 4b115efc], test_signing_cert_fingerprint_formats[SHA-256: 89d38afd9be50adf1833628e825a05869ccdb2d85254cdf07209cae14b115efc] |
| FND-07 | Scheduler framework (Celery) with retries | ✅ PASS | test_follow_up_queued_after_scan, test_logo_alone_runs_immediately, test_logo_follows_domain_scan, test_scan_runs_recorded |
| FND-08 | REST APIs for the dashboard | ✅ PASS | test_openapi_documents_every_endpoint |
| FND-09 | PostgreSQL + Redis | ✅ VERIFIED | PostgreSQL + Redis services — `deploy/docker-compose.yml` |
| FND-10 | Object storage for screenshots and evidence | ✅ VERIFIED | S3-compatible evidence store service — `deploy/docker-compose.yml` |
| FND-11 | Playwright headless browser for screenshots | ✅ PASS | test_ac03_live_phishing_domain_screenshot_and_score |
| FND-12 | Evidence collection: screenshots, metadata, logs | ✅ PASS | 14cc:f4c0-False], 1]/], 7f00:1-True], a00:5-True], a9fe:a9fe-True], test_ac03_live_phishing_domain_screenshot_and_score, test_alert_detail_has_scoring_explanation, test_allowlisted_private_host, test_blocks_internal_destinations[http://127.0.0.1/], test_blocks_internal_destinations[http://evil.test/], test_blocks_internal_destinations[http://loop.test/], test_blocks_internal_destinations[http://meta.test/latest/meta-data], test_blocks_non_http_schemes[file:///etc/passwd], test_blocks_non_http_schemes[ftp://example.com/x], test_blocks_non_http_schemes[gopher://x], test_follows_public_redirects, test_gives_up_after_retries, test_redirect_to_internal_host_is_blocked, test_retries_server_errors_then_succeeds, test_size_cap |
| FND-13 | Logging and error handling | ✅ PASS | 14cc:f4c0-False], 1]/], 7f00:1-True], a00:5-True], a9fe:a9fe-True], test_allowlisted_private_host, test_blocks_internal_destinations[http://127.0.0.1/], test_blocks_internal_destinations[http://evil.test/], test_blocks_internal_destinations[http://loop.test/], test_blocks_internal_destinations[http://meta.test/latest/meta-data], test_blocks_non_http_schemes[file:///etc/passwd], test_blocks_non_http_schemes[ftp://example.com/x], test_blocks_non_http_schemes[gopher://x], test_follows_public_redirects, test_gives_up_after_retries, test_health_and_request_ids, test_redirect_to_internal_host_is_blocked, test_retries_server_errors_then_succeeds, test_scan_runs_recorded, test_size_cap |
| FND-14 | Performance optimization | ✅ VERIFIED | Performance notes and measured timings — `docs/guides/OPERATIONS.md` |
| FND-15 | Deployment to staging/production | ✅ PASS | test_production_refuses_default_secrets |

### N. Acceptance criteria (§9) — must pass by end of Phase 1

| ID | Requirement | Result | Evidence |
|---|---|---|---|
| AC-01 | Typosquat: detects generated variants for configured brand | ✅ PASS | test_ac01_typosquat_variants_detected |
| AC-02 | MX: resolves and stores MX records | ✅ PASS | test_ac02_mx_records_resolved_and_stored |
| AC-03 | Active phishing: screenshot + risk score for live suspicious domain | ✅ PASS | test_ac03_live_phishing_domain_screenshot_and_score |
| AC-04 | Fake APK: detects at least one simulated fake APK entry | ✅ PASS | test_ac04_simulated_fake_apk_detected |
| AC-05 | Rogue app: detects unauthorized listing by keyword | ✅ PASS | test_ac05_unauthorized_play_listing_by_keyword |
| AC-06 | Social: detects simulated fake social account | ✅ PASS | test_ac06_simulated_fake_social_account |
| AC-07 | Documents: detects indexed document containing brand keyword | ✅ PASS | test_ac07_indexed_document_with_brand_keyword |
| AC-08 | Logo: detects official logo on a test website | ✅ PASS | test_ac08_official_logo_on_test_website |
| AC-09 | Dashboard displays alerts from all modules | ✅ PASS | test_ac09_alerts_exist_for_all_modules, test_alert_queue_filters_and_search |
| AC-10 | Analyst can change alert status | ✅ PASS | test_ac10_analyst_changes_alert_status |

### O. Final deliverables (§10)

| ID | Requirement | Result | Evidence |
|---|---|---|---|
| DEL-01 | Operational web application | ✅ VERIFIED | Web application — `frontend/package.json` |
| DEL-02 | Source code repository | ✅ VERIFIED | Source code repository — `README.md` |
| DEL-03 | Database schema & migration scripts | ✅ VERIFIED | Schema & migration scripts — `docs/guides/DATA-MODEL.md` |
| DEL-04 | API documentation | ✅ PASS | test_openapi_documents_every_endpoint |
| DEL-05 | Deployment guide | ✅ VERIFIED | Deployment guide — `docs/guides/DEPLOYMENT.md` |
| DEL-06 | Configuration guide for new brands | ✅ VERIFIED | Configuration guide for new brands — `docs/guides/BRAND-CONFIGURATION.md` |
| DEL-07 | Test report / UAT report | ✅ VERIFIED | Test / UAT report — `docs/reports/UAT-REPORT.md` |
| DEL-08 | Sample monitoring data for demonstration | ✅ VERIFIED | Sample monitoring data: fictional test brand + simulated sources, inside the test suite only (D-32) — `backend/tests/support/seed_test_brand.py` |

### P. Phishing email monitoring (Phase-1.5, D-28) — spec `docs/superpowers/specs/2026-10-08-phishing-email-design.md`

| ID | Requirement | Result | Evidence |
|---|---|---|---|
| EML-01 | Parse uploaded .eml/.msg emails (headers, bodies, attachments) | ✅ PASS | test_attachment_limit, test_attachments_hashed_and_archive_listed, test_extract_urls_from_text_and_html, test_forwarded_original_is_analysed, test_garbage_input_is_handled, test_headers_and_sender, test_links_extracted_unwrapped_and_deobfuscated, test_malformed_mime_does_not_crash, test_unwrap[https://a.test/plain-https://a.test/plain], test_unwrap[https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fa.test%2Fb&data=1-https://a.test/b], test_unwrap[https://urldefense.proofpoint.com/v2/url?u=https-3A__a.test_d&d=x-https://a.test/d], test_unwrap[https://www.google.com/url?q=https://a.test/c&sa=D-https://a.test/c], test_unwrap[hxxp://a[.]test/e-http://a.test/e] |
| EML-02 | Extract and unwrap URLs (Safe Links, Proofpoint, Google, hxxp/[.]) | ✅ PASS | test_attachment_limit, test_attachments_hashed_and_archive_listed, test_extract_urls_from_text_and_html, test_forwarded_original_is_analysed, test_garbage_input_is_handled, test_headers_and_sender, test_links_extracted_unwrapped_and_deobfuscated, test_malformed_mime_does_not_crash, test_unwrap[https://a.test/plain-https://a.test/plain], test_unwrap[https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fa.test%2Fb&data=1-https://a.test/b], test_unwrap[https://urldefense.proofpoint.com/v2/url?u=https-3A__a.test_d&d=x-https://a.test/d], test_unwrap[https://www.google.com/url?q=https://a.test/c&sa=D-https://a.test/c], test_unwrap[hxxp://a[.]test/e-http://a.test/e] |
| EML-03 | Analyse the attached original of a forwarded report | ✅ PASS | test_attachment_limit, test_attachments_hashed_and_archive_listed, test_extract_urls_from_text_and_html, test_forwarded_original_is_analysed, test_garbage_input_is_handled, test_headers_and_sender, test_links_extracted_unwrapped_and_deobfuscated, test_malformed_mime_does_not_crash, test_unwrap[https://a.test/plain-https://a.test/plain], test_unwrap[https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fa.test%2Fb&data=1-https://a.test/b], test_unwrap[https://urldefense.proofpoint.com/v2/url?u=https-3A__a.test_d&d=x-https://a.test/d], test_unwrap[https://www.google.com/url?q=https://a.test/c&sa=D-https://a.test/c], test_unwrap[hxxp://a[.]test/e-http://a.test/e] |
| EML-04 | Read SPF/DKIM/DMARC from Authentication-Results | ✅ PASS | test_dmarc_fail_when_from_fails_all, test_dmarc_pass_with_aligned_spf, test_dns_failure_is_temperror_not_exception, test_no_dmarc_record_is_none_result, test_reads_header_verdicts |
| EML-05 | Independent DMARC alignment evaluation | ✅ PASS | test_dmarc_fail_when_from_fails_all, test_dmarc_pass_with_aligned_spf, test_dns_failure_is_temperror_not_exception, test_no_dmarc_record_is_none_result, test_reads_header_verdicts |
| EML-06 | Rspamd spam/phishing scoring | ✅ PASS | test_clamav_clean, test_clamav_detects, test_clamav_disabled, test_rspamd_clean_is_not_malicious, test_rspamd_down_is_not_checked, test_rspamd_flags_phishing, test_yara_matches_rule |
| EML-07 | ClamAV attachment malware scan | ✅ PASS | test_clamav_clean, test_clamav_detects, test_clamav_disabled, test_rspamd_clean_is_not_malicious, test_rspamd_down_is_not_checked, test_rspamd_flags_phishing, test_yara_matches_rule |
| EML-08 | YARA phishing/malware pattern rules | ✅ PASS | test_clamav_clean, test_clamav_detects, test_clamav_disabled, test_rspamd_clean_is_not_malicious, test_rspamd_down_is_not_checked, test_rspamd_flags_phishing, test_yara_matches_rule |
| EML-09 | Threat intel: URLhaus, OpenPhish, urlscan.io, AbuseIPDB (cached, corroborated) | ✅ PASS | test_abuseipdb_high_confidence, test_corroborated_counts_distinct_malicious_tools, test_no_key_is_not_checked, test_openphish_hit, test_quota_error_is_not_checked, test_urlhaus_known_url, test_urlhaus_unknown_url, test_urlscan_malicious_verdict |
| EML-10 | Deterministic risk scoring with the 2-source corroboration rule | ✅ PASS | test_auth_fail_from_brand_domain, test_lookalike_phish_is_critical, test_malware_attachment_from_clamav, test_official_email_is_not_impersonation, test_single_source_is_not_known_malicious |
| EML-11 | Official DMARC-pass senders are never scored as impersonation | ✅ PASS | test_auth_fail_from_brand_domain, test_lookalike_phish_is_critical, test_malware_attachment_from_clamav, test_official_email_is_not_impersonation, test_single_source_is_not_known_malicious |
| EML-12 | Email scoring rules in the shared model | ✅ PASS | test_email_modules_use_all_four_levels[dmarc], test_email_modules_use_all_four_levels[email], test_email_modules_use_all_four_levels[email_posture], test_email_rules[signals0-40-known_malicious_url], test_email_rules[signals1-15-single_source_url_hit], test_email_rules[signals10-10-bad_sender_ip], test_email_rules[signals11-10-rspamd_phish], test_email_rules[signals12-20-live_phishing_page], test_email_rules[signals13-10-lookalike_can_send], test_email_rules[signals14-40-posture_dmarc_missing], test_email_rules[signals15-20-posture_dmarc_none], test_email_rules[signals16-40-posture_spf_missing], test_email_rules[signals17-10-posture_spf_softfail], test_email_rules[signals18-10-posture_dkim_missing], test_email_rules[signals19-5-posture_mta_sts_missing], test_email_rules[signals2-40-malware_attachment], test_email_rules[signals3-20-suspicious_attachment], test_email_rules[signals4-30-auth_fail_brand_from], test_email_rules[signals5-25-lookalike_sender], test_email_rules[signals6-20-brand_impersonation], test_email_rules[signals7-10-reply_to_mismatch], test_email_rules[signals8-15-credential_or_payment_language], test_email_rules[signals9-10-young_domain], test_typical_phish_is_critical |
| EML-13 | Upload API, storage of raw .eml, dedupe | ✅ PASS | test_failed_analysis_is_marked_failed_not_left_queued, test_non_email_file_rejected, test_official_email_low_risk, test_same_email_twice_updates_one_alert, test_unknown_brand, test_upload_creates_email_alert_with_evidence |
| EML-14 | Email alert with evidence and the module's output fields | ✅ PASS | test_failed_analysis_is_marked_failed_not_left_queued, test_non_email_file_rejected, test_official_email_low_risk, test_same_email_twice_updates_one_alert, test_unknown_brand, test_upload_creates_email_alert_with_evidence |
| EML-15 | Brand domain email posture (SPF/DMARC/DKIM/MTA-STS) | ✅ PASS | test_duplicate_dmarc_record_is_missing, test_missing_spf_and_dmarc_is_high_risk, test_softfail_spf_and_none_policy, test_well_configured_domain_no_alert |
| EML-16 | Detect duplicate/invalid/`p=none` DMARC and permissive SPF | ✅ PASS | test_duplicate_dmarc_record_is_missing, test_missing_spf_and_dmarc_is_high_risk, test_softfail_spf_and_none_policy, test_well_configured_domain_no_alert |
| EML-17 | Look-alike domains flagged when email-ready (SPF present) | ✅ PASS | test_domain_with_mx_only_can_receive_not_send, test_domain_with_spf_can_send, test_unrelated_txt_is_not_spf |
| EML-18 | DMARC aggregate report parsing (xml/gz/zip, XML-bomb safe) | ✅ PASS | test_parse_gzip, test_parse_plain_xml, test_parse_zip, test_xml_bomb_rejected |
| EML-19 | IMAP reporting-mailbox intake | ✅ PASS | test_fetch_new_returns_unseen, test_second_poll_skips_seen |
| EML-20 | Dashboard: emails page, email alert view, email-security panel | ✅ VERIFIED | Email dashboard pages (upload, list, detail, brand email-security panel) — `frontend/src/app/(app)/emails/page.tsx` |

### Q. Real data, accuracy and explainability (owner addendum 2026-10-09) — roadmap sub-projects SP1–SP5

| ID | Requirement | Result | Evidence |
|---|---|---|---|
| RDA-01 | Dashboard and APIs show only real scan results / DB records — no demo, mock or fallback findings, statistics, screenshots or responses | ✅ PASS | test_brand_api_has_no_demo_mode, test_brand_schemas_reject_demo_mode, test_product_code_has_no_demo_or_fixture_paths, test_settings_have_no_demo_switch |
| RDA-02 | Empty state "No threats detected." when there are no findings; zero shows as zero | ✅ PASS | test_dashboard_reports_scan_coverage, test_failed_latest_scan_blocks_no_threats_claim |
| RDA-03 | An unconfigured, rate-limited, unavailable or failed integration is shown with its status and error, never as "no threats found"; other scanners continue | ✅ PASS | test_all_ok_components_complete, test_all_ok_is_completed, test_apk_keeps_results_of_searches_that_worked, test_apk_scan_fails_when_every_search_is_unavailable, test_apk_store_search_keeps_scan_alive_when_web_search_is_down, test_blocked_telegram_pages_are_not_reported_as_not_found, test_capture_failure_leaves_existing_alert_untouched, test_capture_failure_on_new_domain_is_unknown_not_offline, test_components_keep_insertion_order, test_crash_fails_run, test_ct_failure_and_whois_error_are_reported, test_dns_timeout_is_unresolved_not_unregistered, test_documents_scan_fails_when_every_search_is_unavailable, test_email_tool_status_comes_from_latest_analysed_email, test_errors_lists_failed_and_unavailable_messages, test_failure_beats_reduced_coverage, test_fatal_component_fails_run, test_fatal_unavailable_fails_run, test_last_status_comes_from_latest_scan_component, test_lists_every_integration_with_configuration, test_logo_fails_when_no_target_page_could_be_captured, test_logo_without_official_logo_is_not_configured_and_fails, test_no_components_is_completed, test_not_configured_is_partially_completed, test_page_timeout_is_unknown_not_offline, test_page_timeout_leaves_existing_alert_untouched, test_repeated_component_keeps_worst_status_and_sums_counts, test_rogue_app_fails_when_every_store_search_fails, test_skipped_alone_is_completed, test_social_with_every_source_down_fails, test_social_without_telegram_credentials_is_not_configured, test_total_dns_outage_fails_the_run, test_txt_nxdomain_is_a_definitive_empty_answer, test_txt_timeout_is_unknown_not_missing, test_unavailable_is_partially_completed, test_unconfigured_search_is_not_configured_not_unavailable |
| RDA-04 | Test data stays inside test code; never seeds or appears in the application; the app works with an empty database | ✅ PASS | test_brand_api_has_no_demo_mode, test_brand_schemas_reject_demo_mode, test_product_code_has_no_demo_or_fixture_paths, test_settings_have_no_demo_switch |
| RDA-05 | Inspect the existing implementation first; enhance existing features instead of duplicating them | ⚠️ OPEN | No evidence yet |
| RDA-06 | Quality review and improvement of every existing scanner | ⚠️ OPEN | No evidence yet |
| RDA-07 | Multi-signal detection for domains/websites (domain, DNS/infrastructure, website, threat-intel, visual signals) | ⚠️ OPEN | No evidence yet |
| RDA-08 | Separate Risk Score and Confidence Score | ⚠️ OPEN | No evidence yet |
| RDA-09 | Every score explained with reasons traceable to real evidence | ⚠️ OPEN | No evidence yet |
| RDA-10 | False-positive reduction: independent signals, source reliability, history, allowlists, analyst decisions | ⚠️ OPEN | No evidence yet |
| RDA-11 | Analyst decisions Confirmed Threat, False Positive, Legitimate, Ignored, Investigating, Reopened — preserved and used as context | ✅ PASS | test_closed_decision_suppresses_until_meaningful_change_reopens, test_false_positive_path, test_findings_api_filters_decisions_and_allowlist |
| RDA-12 | Candidate → Finding → Alert separation; alerts only when criteria are met | ✅ PASS | test_brand_alert_level_holds_back_lower_findings, test_candidate_never_alerts_and_promotion_alerts, test_findings_api_filters_decisions_and_allowlist |
| RDA-13 | Alert carries the minimum actionable information (IDs, brand, threat type, target, risk, confidence, severity, times, reasons, evidence, source, indicators, TI matches, related findings, scan ID, status) | ⚠️ OPEN | No evidence yet |
| RDA-14 | No double counting: one finding per entity across sources; multiple sources raise confidence, not risk | ⚠️ OPEN | No evidence yet |
| RDA-15 | Rescan: match entity, store observation, update last_seen, diff state, recalculate, timeline, alert only on meaningful change or threshold crossing | ✅ PASS | test_meaningful_change_raises_new_alert_on_timeline, test_rescan_stores_observation_without_new_finding_or_alert, test_unknown_state_is_not_a_change |
| RDA-16 | Cross-module correlation into campaigns; correlation raises confidence | ⚠️ OPEN | No evidence yet |
| RDA-17 | Real scan states (queued, running, completed, completed_with_errors, partially_completed, failed, cancelled) with per-component status | ✅ PASS | test_all_ok_components_complete, test_all_ok_is_completed, test_apk_keeps_results_of_searches_that_worked, test_apk_scan_fails_when_every_search_is_unavailable, test_apk_store_search_keeps_scan_alive_when_web_search_is_down, test_blocked_telegram_pages_are_not_reported_as_not_found, test_capture_failure_leaves_existing_alert_untouched, test_capture_failure_on_new_domain_is_unknown_not_offline, test_components_keep_insertion_order, test_crash_fails_run, test_ct_failure_and_whois_error_are_reported, test_dashboard_reports_scan_coverage, test_dns_timeout_is_unresolved_not_unregistered, test_documents_scan_fails_when_every_search_is_unavailable, test_errors_lists_failed_and_unavailable_messages, test_failed_latest_scan_blocks_no_threats_claim, test_failure_beats_reduced_coverage, test_fatal_component_fails_run, test_fatal_unavailable_fails_run, test_interrupted_run_is_cancelled_not_failed, test_logo_fails_when_no_target_page_could_be_captured, test_logo_without_official_logo_is_not_configured_and_fails, test_no_components_is_completed, test_not_configured_is_partially_completed, test_page_timeout_is_unknown_not_offline, test_page_timeout_leaves_existing_alert_untouched, test_repeated_component_keeps_worst_status_and_sums_counts, test_rogue_app_fails_when_every_store_search_fails, test_scan_runs_recorded, test_scan_that_could_not_be_queued_is_finished, test_scans_api_returns_components, test_skipped_alone_is_completed, test_social_with_every_source_down_fails, test_social_without_telegram_credentials_is_not_configured, test_total_dns_outage_fails_the_run, test_txt_nxdomain_is_a_definitive_empty_answer, test_txt_timeout_is_unknown_not_missing, test_unavailable_is_partially_completed, test_unconfigured_search_is_not_configured_not_unavailable |
| RDA-18 | Evidence preserved and linked to the right finding (HTTP headers, redirect chain, IP/ASN, TI responses, APK permissions/URLs, document metadata, scan logs) | ⚠️ OPEN | No evidence yet |
| RDA-19 | Frontend shows an error state when the backend fails and an empty state when it returns nothing — no fake fallbacks | ⚠️ OPEN | No evidence yet |
| RDA-20 | Scanner lifecycle (discovery → validation → normalization → dedup → analysis → evidence → risk → confidence → correlation → persistence → alert decision → workflow) with structured evidence | ⚠️ OPEN | No evidence yet |
| RDA-21 | Tool failures captured and recorded; never fabricated, never marked successful, never turned into findings | ✅ PASS | test_all_ok_components_complete, test_all_ok_is_completed, test_apk_keeps_results_of_searches_that_worked, test_apk_scan_fails_when_every_search_is_unavailable, test_apk_store_search_keeps_scan_alive_when_web_search_is_down, test_blocked_telegram_pages_are_not_reported_as_not_found, test_capture_failure_leaves_existing_alert_untouched, test_capture_failure_on_new_domain_is_unknown_not_offline, test_components_keep_insertion_order, test_crash_fails_run, test_ct_failure_and_whois_error_are_reported, test_dns_timeout_is_unresolved_not_unregistered, test_documents_scan_fails_when_every_search_is_unavailable, test_errors_lists_failed_and_unavailable_messages, test_failed_analysis_is_marked_failed_not_left_queued, test_failure_beats_reduced_coverage, test_fatal_component_fails_run, test_fatal_unavailable_fails_run, test_logo_fails_when_no_target_page_could_be_captured, test_logo_without_official_logo_is_not_configured_and_fails, test_no_components_is_completed, test_not_configured_is_partially_completed, test_page_timeout_is_unknown_not_offline, test_page_timeout_leaves_existing_alert_untouched, test_repeated_component_keeps_worst_status_and_sums_counts, test_rogue_app_fails_when_every_store_search_fails, test_skipped_alone_is_completed, test_social_with_every_source_down_fails, test_social_without_telegram_credentials_is_not_configured, test_total_dns_outage_fails_the_run, test_txt_nxdomain_is_a_definitive_empty_answer, test_txt_timeout_is_unknown_not_missing, test_unavailable_is_partially_completed, test_unconfigured_search_is_not_configured_not_unavailable |
| RDA-22 | Implementation priority and final rule (prefer "no threat detected" / "unable to scan" / "insufficient evidence" over overstated results) | ✅ PASS | test_failed_latest_scan_blocks_no_threats_claim |
| RDA-23 | Beginner-friendly handbook: one folder per module, tools and reasons, gaps, end-to-end process, PDF-ready | ✅ VERIFIED | Beginner-friendly handbook, one folder per chapter — `docs/handbook/README.md` |

### R. Social media brand-misuse monitor (owner request 2026-10-09) — spec `docs/superpowers/specs/2026-10-09-social-media-monitor-design.md`

| ID | Requirement | Result | Evidence |
|---|---|---|---|
| SMM-01 | One Social Media section showing posts, videos, ads, channels and accounts that misuse the brand, each with a screenshot and a link | ✅ PASS | test_scam_video_is_flagged_with_screenshot_and_alert_level |
| SMM-02 | Platforms: YouTube, Facebook, Instagram, X, Threads, Meta ads, Pinterest, TikTok, LinkedIn, Telegram (official API when a key is configured, web search otherwise) | ✅ PASS | test_facebook_pages_source, test_scam_video_is_flagged_with_screenshot_and_alert_level |
| SMM-03 | Detect fake contact details (phone, WhatsApp, Telegram, UPI) and scam wording next to the brand | ✅ PASS | test_contact_details_and_scam_wording, test_scam_video_is_flagged_with_screenshot_and_alert_level, test_short_brand_name_with_scam_contact_is_kept |
| SMM-04 | Skip the brand's own accounts/channels (allowlist) and content that does not reference the brand | ✅ PASS | test_official_irrelevant_and_mention_only |
| SMM-05 | A source without a key is reported "not configured", never "nothing found" (D-31) | ✅ PASS | test_facebook_pages_source, test_no_source_checked_fails_the_run |
| SMM-06 | Video evidence = link + thumbnail + screenshot; no video download | ✅ PASS | test_scam_video_is_flagged_with_screenshot_and_alert_level |

## 3. Automated test log

| Test | Result | Requirements | Seconds |
|---|---|---|---|
| `tests/api/test_api.py::test_ac10_analyst_changes_alert_status` | passed | AC-10, D-07, DSH-10 | 0.35 |
| `tests/api/test_api.py::test_admin_manages_users` | passed | FND-03 | 0.18 |
| `tests/api/test_api.py::test_alert_detail_has_scoring_explanation` | passed | DSH-08, FND-12 | 0.07 |
| `tests/api/test_api.py::test_alert_queue_filters_and_search` | passed | AC-09, DSH-07, DSH-09, DSH-11, DSH-12, DSH-13, DSH-14, DSH-15, DSH-16, DSH-21 | 0.55 |
| `tests/api/test_api.py::test_analyst_cannot_administer` | passed | D-15, FND-03 | 0.18 |
| `tests/api/test_api.py::test_brand_api_has_no_demo_mode` | passed | D-27, D-32, RDA-01, RDA-04 | 0.09 |
| `tests/api/test_api.py::test_brand_onboarding_with_logo_and_allowlists` | passed | FND-04, FND-05, FND-06, OUT-01 | 1.5 |
| `tests/api/test_api.py::test_csv_export_matches_filters` | passed | DSH-18 | 0.15 |
| `tests/api/test_api.py::test_executive_dashboard_numbers` | passed | DSH-01, DSH-02, DSH-03, DSH-04, DSH-05, DSH-06, DSH-17 | 0.32 |
| `tests/api/test_api.py::test_false_positive_path` | passed | D-07, DSH-10, RDA-11 | 0.19 |
| `tests/api/test_api.py::test_health_and_request_ids` | passed | FND-13 | 0.02 |
| `tests/api/test_api.py::test_login_and_protected_routes` | passed | D-15, FND-03 | 0.57 |
| `tests/api/test_api.py::test_openapi_documents_every_endpoint` | passed | DEL-04, FND-08 | 0.42 |
| `tests/api/test_api.py::test_pdf_export_html_renders_all_rows` | passed | DSH-19 | 1.59 |
| `tests/api/test_auto_scan.py::test_master_switch_and_brand_settings_api` | passed | D-39 | 0.25 |
| `tests/api/test_auto_scan.py::test_plan_respects_switch_frequency_and_scanners` | passed | D-39 | 0.0 |
| `tests/api/test_emails_api.py::test_failed_analysis_is_marked_failed_not_left_queued` | passed | EML-13, EML-14, RDA-21 | 0.04 |
| `tests/api/test_emails_api.py::test_non_email_file_rejected` | passed | EML-13, EML-14 | 0.15 |
| `tests/api/test_emails_api.py::test_official_email_low_risk` | passed | EML-13, EML-14 | 0.72 |
| `tests/api/test_emails_api.py::test_same_email_twice_updates_one_alert` | passed | EML-13, EML-14 | 1.44 |
| `tests/api/test_emails_api.py::test_unknown_brand` | passed | EML-13, EML-14 | 0.15 |
| `tests/api/test_emails_api.py::test_upload_creates_email_alert_with_evidence` | passed | EML-13, EML-14 | 1.11 |
| `tests/api/test_findings.py::test_brand_alert_level_holds_back_lower_findings` | passed | D-34, RDA-12 | 0.03 |
| `tests/api/test_findings.py::test_candidate_never_alerts_and_promotion_alerts` | passed | D-33, RDA-12 | 0.06 |
| `tests/api/test_findings.py::test_closed_decision_suppresses_until_meaningful_change_reopens` | passed | D-35, D-36, RDA-11 | 0.1 |
| `tests/api/test_findings.py::test_findings_api_filters_decisions_and_allowlist` | passed | D-35, RDA-11, RDA-12 | 0.44 |
| `tests/api/test_findings.py::test_meaningful_change_raises_new_alert_on_timeline` | passed | D-36, RDA-15 | 0.08 |
| `tests/api/test_findings.py::test_rescan_stores_observation_without_new_finding_or_alert` | passed | D-36, RDA-15 | 0.06 |
| `tests/api/test_findings.py::test_unknown_state_is_not_a_change` | passed | D-31, RDA-15 | 0.06 |
| `tests/api/test_integrations_api.py::test_email_tool_status_comes_from_latest_analysed_email` | passed | RDA-03 | 0.04 |
| `tests/api/test_integrations_api.py::test_last_status_comes_from_latest_scan_component` | passed | RDA-03 | 0.04 |
| `tests/api/test_integrations_api.py::test_lists_every_integration_with_configuration` | passed | RDA-03 | 0.04 |
| `tests/api/test_scans_api.py::test_dashboard_reports_scan_coverage` | passed | RDA-02, RDA-17 | 0.21 |
| `tests/api/test_scans_api.py::test_failed_latest_scan_blocks_no_threats_claim` | passed | RDA-02, RDA-17, RDA-22 | 0.6 |
| `tests/api/test_scans_api.py::test_interrupted_run_is_cancelled_not_failed` | passed | RDA-17 | 0.04 |
| `tests/api/test_scans_api.py::test_scan_that_could_not_be_queued_is_finished` | passed | RDA-17 | 0.06 |
| `tests/api/test_scans_api.py::test_scans_api_returns_components` | passed | RDA-17 | 0.06 |
| `tests/modules/test_acceptance.py::test_ac01_typosquat_variants_detected` | passed | AC-01, OBJ-01, TYP-01, TYP-02, TYP-03, TYP-04, TYP-05, TYP-06, TYP-07, TYP-08, TYP-12 | 0.01 |
| `tests/modules/test_acceptance.py::test_ac02_mx_records_resolved_and_stored` | passed | AC-02, MX-01, MX-02, MX-03, MX-04 | 0.02 |
| `tests/modules/test_acceptance.py::test_ac03_live_phishing_domain_screenshot_and_score` | passed | AC-03, FND-11, FND-12, OBJ-02, PHI-01, PHI-02, PHI-03, PHI-04, PHI-05, PHI-06, PHI-07, PHI-08, PHI-09 | 0.01 |
| `tests/modules/test_acceptance.py::test_ac04_simulated_fake_apk_detected` | passed | AC-04, APK-01, APK-02, APK-03, APK-04, APK-05, APK-06, APK-07, APK-08, APK-09, OBJ-03 | 0.01 |
| `tests/modules/test_acceptance.py::test_ac05_unauthorized_play_listing_by_keyword` | passed | AC-05, ROG-01, ROG-03, ROG-04, ROG-05, ROG-06 | 0.02 |
| `tests/modules/test_acceptance.py::test_ac06_simulated_fake_social_account` | passed | AC-06, OBJ-04, SOC-01, SOC-02, SOC-03, SOC-04, SOC-05, SOC-06, SOC-07, SOC-08, SOC-09, SOC-10, SOC-11, SOC-12 | 0.01 |
| `tests/modules/test_acceptance.py::test_ac07_indexed_document_with_brand_keyword` | passed | AC-07, DOC-01, DOC-02, DOC-03, DOC-04, DOC-05, DOC-06, DOC-07, DOC-08, OBJ-05 | 0.01 |
| `tests/modules/test_acceptance.py::test_ac08_official_logo_on_test_website` | passed | AC-08, LOGO-01, LOGO-02, LOGO-03, LOGO-04, LOGO-05, LOGO-06, OBJ-06 | 0.01 |
| `tests/modules/test_acceptance.py::test_ac09_alerts_exist_for_all_modules` | passed | AC-09, DSH-21, OBJ-07 | 0.01 |
| `tests/modules/test_acceptance.py::test_branded_phishing_page_reports_brand_evidence` | passed | D-29 | 0.01 |
| `tests/modules/test_acceptance.py::test_newly_registered_domain_from_certificate_transparency` | passed | D-11, TYP-09, TYP-10, TYP-11, TYP-13 | 0.01 |
| `tests/modules/test_acceptance.py::test_parked_lookalike_scores_low` | passed | D-29, RSK-09 | 0.01 |
| `tests/modules/test_acceptance.py::test_repackaged_official_app_detected_by_signature` | passed | APK-02, APK-06, APK-07, D-26 | 0.01 |
| `tests/modules/test_acceptance.py::test_rescan_updates_instead_of_duplicating` | passed | D-19, D-21 | 0.29 |
| `tests/modules/test_acceptance.py::test_rogue_app_removed_is_tracked` | passed | ROG-05 | 0.08 |
| `tests/modules/test_acceptance.py::test_scan_runs_recorded` | passed | FND-07, FND-13, RDA-17 | 0.01 |
| `tests/modules/test_acceptance.py::test_unrelated_live_site_capped_at_medium` | passed | D-29, RSK-09 | 0.01 |
| `tests/modules/test_acceptance.py::test_unrelated_live_site_is_not_suspected_phishing` | passed | D-04, PHI-08 | 0.01 |
| `tests/modules/test_social_media.py::test_contact_details_and_scam_wording` | passed | SMM-03 | 0.0 |
| `tests/modules/test_social_media.py::test_facebook_pages_source` | passed | SMM-02, SMM-05 | 0.0 |
| `tests/modules/test_social_media.py::test_no_source_checked_fails_the_run` | passed | D-31, SMM-05 | 0.0 |
| `tests/modules/test_social_media.py::test_official_irrelevant_and_mention_only` | passed | SMM-04 | 0.0 |
| `tests/modules/test_social_media.py::test_scam_video_is_flagged_with_screenshot_and_alert_level` | passed | SMM-01, SMM-02, SMM-03, SMM-06 | 0.0 |
| `tests/modules/test_social_media.py::test_short_brand_name_with_scam_contact_is_kept` | passed | SMM-03 | 0.0 |
| `tests/unit/test_allowlist.py::test_normalize[domain-chitkart.com-chitkart.com]` | passed | FND-06 | 0.0 |
| `tests/unit/test_allowlist.py::test_normalize[domain-https://www.MyKCPL.com/login-mykcpl.com]` | passed | FND-06 | 0.0 |
| `tests/unit/test_allowlist.py::test_normalize[email_domain-support@mykcpl.com-mykcpl.com]` | passed | FND-06 | 0.0 |
| `tests/unit/test_allowlist.py::test_normalize[package-com.Zentrova.Mobile-com.zentrova.mobile]` | passed | FND-06 | 0.0 |
| `tests/unit/test_allowlist.py::test_normalize[package-https://play.google.com/store/apps/details?id=com.bharatchits.androidapp&hl=en-com.bharatchits.androidapp]` | passed | FND-06 | 0.0 |
| `tests/unit/test_allowlist.py::test_normalize[publisher- Kodachadri Fintech Pvt Ltd -Kodachadri Fintech Pvt Ltd]` | passed | FND-06 | 0.0 |
| `tests/unit/test_allowlist.py::test_normalize[social_handle-@ZentrovaBank-zentrovabank]` | passed | FND-06 | 0.0 |
| `tests/unit/test_allowlist.py::test_normalize[social_handle-https://t.me/zentrova_news-zentrova_news]` | passed | FND-06 | 0.0 |
| `tests/unit/test_allowlist.py::test_normalize[social_handle-https://www.facebook.com/kodachadrichitsofficial/-kodachadrichitsofficial]` | passed | FND-06 | 0.0 |
| `tests/unit/test_allowlist.py::test_normalize[social_handle-https://www.instagram.com/chit_kart/-chit_kart]` | passed | FND-06 | 0.0 |
| `tests/unit/test_allowlist.py::test_normalize[social_handle-https://www.instagram.com/kodachadrichits/-kodachadrichits]` | passed | FND-06 | 0.0 |
| `tests/unit/test_allowlist.py::test_normalize[social_handle-https://www.linkedin.com/company/chitkart/?original_referer=-chitkart]` | passed | FND-06 | 0.0 |
| `tests/unit/test_allowlist.py::test_normalize[social_handle-https://www.linkedin.com/company/kodachadrichits/-kodachadrichits]` | passed | FND-06 | 0.0 |
| `tests/unit/test_allowlist.py::test_normalize[social_handle-https://www.youtube.com/@kodachadrichitsofficial-kodachadrichitsofficial]` | passed | FND-06 | 0.0 |
| `tests/unit/test_allowlist.py::test_normalize[social_handle-https://x.com/ZentrovaBank-zentrovabank]` | passed | FND-06 | 0.0 |
| `tests/unit/test_allowlist.py::test_normalize[social_handle-instagram.com/zentrova/-zentrova]` | passed | FND-06 | 0.0 |
| `tests/unit/test_allowlist.py::test_normalize[social_handle-zentrova_official-zentrova_official]` | passed | FND-06 | 0.0 |
| `tests/unit/test_allowlist.py::test_signing_cert_fingerprint_formats[89:D3:8A:FD:9B:E5:0A:DF:18:33:62:8E:82:5A:05:86:9C:CD:B2:D8:52:54:CD:F0:72:09:CA:E1:4B:11:5E:FC]` | passed | D-26, FND-06 | 0.0 |
| `tests/unit/test_allowlist.py::test_signing_cert_fingerprint_formats[89d38afd 9be50adf 1833628e 825a0586 9ccdb2d8 5254cdf0 7209cae1 4b115efc]` | passed | D-26, FND-06 | 0.0 |
| `tests/unit/test_allowlist.py::test_signing_cert_fingerprint_formats[SHA-256: 89d38afd9be50adf1833628e825a05869ccdb2d85254cdf07209cae14b115efc]` | passed | D-26, FND-06 | 0.0 |
| `tests/unit/test_commoncrawl.py::test_archived_html_is_read_from_the_warc_record` | passed | APK-01 | 0.0 |
| `tests/unit/test_commoncrawl.py::test_find_pages_paced_and_reports` | passed | APK-01, D-31 | 0.0 |
| `tests/unit/test_commoncrawl.py::test_slugs_keep_shortest_roots` | passed | APK-01 | 0.0 |
| `tests/unit/test_dmarc.py::test_parse_gzip` | passed | EML-18 | 0.0 |
| `tests/unit/test_dmarc.py::test_parse_plain_xml` | passed | EML-18 | 0.0 |
| `tests/unit/test_dmarc.py::test_parse_zip` | passed | EML-18 | 0.0 |
| `tests/unit/test_dmarc.py::test_xml_bomb_rejected` | passed | EML-18 | 0.0 |
| `tests/unit/test_domain_reporting.py::test_all_ok_components_complete` | passed | RDA-03, RDA-17, RDA-21 | 0.34 |
| `tests/unit/test_domain_reporting.py::test_capture_failure_leaves_existing_alert_untouched` | passed | RDA-03, RDA-17, RDA-21 | 0.33 |
| `tests/unit/test_domain_reporting.py::test_capture_failure_on_new_domain_is_unknown_not_offline` | passed | RDA-03, RDA-17, RDA-21 | 0.64 |
| `tests/unit/test_domain_reporting.py::test_ct_failure_and_whois_error_are_reported` | passed | RDA-03, RDA-17, RDA-21 | 0.41 |
| `tests/unit/test_domain_reporting.py::test_dns_timeout_is_unresolved_not_unregistered` | passed | RDA-03, RDA-17, RDA-21 | 0.47 |
| `tests/unit/test_domain_reporting.py::test_page_timeout_is_unknown_not_offline` | passed | RDA-03, RDA-17, RDA-21 | 0.64 |
| `tests/unit/test_domain_reporting.py::test_page_timeout_leaves_existing_alert_untouched` | passed | RDA-03, RDA-17, RDA-21 | 0.31 |
| `tests/unit/test_domain_reporting.py::test_total_dns_outage_fails_the_run` | passed | RDA-03, RDA-17, RDA-21 | 0.32 |
| `tests/unit/test_email_analysis.py::test_auth_fail_from_brand_domain` | passed | EML-10, EML-11 | 0.2 |
| `tests/unit/test_email_analysis.py::test_lookalike_phish_is_critical` | passed | EML-10, EML-11 | 0.23 |
| `tests/unit/test_email_analysis.py::test_malware_attachment_from_clamav` | passed | EML-10, EML-11 | 0.15 |
| `tests/unit/test_email_analysis.py::test_official_email_is_not_impersonation` | passed | EML-10, EML-11 | 0.09 |
| `tests/unit/test_email_analysis.py::test_single_source_is_not_known_malicious` | passed | EML-10, EML-11 | 0.2 |
| `tests/unit/test_email_auth.py::test_dmarc_fail_when_from_fails_all` | passed | EML-04, EML-05 | 0.0 |
| `tests/unit/test_email_auth.py::test_dmarc_pass_with_aligned_spf` | passed | EML-04, EML-05 | 0.0 |
| `tests/unit/test_email_auth.py::test_dns_failure_is_temperror_not_exception` | passed | EML-04, EML-05 | 0.0 |
| `tests/unit/test_email_auth.py::test_no_dmarc_record_is_none_result` | passed | EML-04, EML-05 | 0.0 |
| `tests/unit/test_email_auth.py::test_reads_header_verdicts` | passed | EML-04, EML-05 | 0.0 |
| `tests/unit/test_email_engines.py::test_clamav_clean` | passed | EML-06, EML-07, EML-08 | 0.0 |
| `tests/unit/test_email_engines.py::test_clamav_detects` | passed | EML-06, EML-07, EML-08 | 0.0 |
| `tests/unit/test_email_engines.py::test_clamav_disabled` | passed | EML-06, EML-07, EML-08 | 0.0 |
| `tests/unit/test_email_engines.py::test_rspamd_clean_is_not_malicious` | passed | EML-06, EML-07, EML-08 | 0.06 |
| `tests/unit/test_email_engines.py::test_rspamd_down_is_not_checked` | passed | EML-06, EML-07, EML-08 | 0.08 |
| `tests/unit/test_email_engines.py::test_rspamd_flags_phishing` | passed | EML-06, EML-07, EML-08 | 0.05 |
| `tests/unit/test_email_engines.py::test_yara_matches_rule` | passed | EML-06, EML-07, EML-08 | 0.02 |
| `tests/unit/test_email_intake.py::test_fetch_new_returns_unseen` | passed | EML-19 | 0.0 |
| `tests/unit/test_email_intake.py::test_second_poll_skips_seen` | passed | EML-19 | 0.0 |
| `tests/unit/test_email_intel.py::test_abuseipdb_high_confidence` | passed | EML-09 | 0.19 |
| `tests/unit/test_email_intel.py::test_corroborated_counts_distinct_malicious_tools` | passed | EML-09 | 0.0 |
| `tests/unit/test_email_intel.py::test_no_key_is_not_checked` | passed | EML-09 | 0.0 |
| `tests/unit/test_email_intel.py::test_openphish_hit` | passed | EML-09 | 0.0 |
| `tests/unit/test_email_intel.py::test_quota_error_is_not_checked` | passed | EML-09 | 0.06 |
| `tests/unit/test_email_intel.py::test_urlhaus_known_url` | passed | EML-09 | 0.06 |
| `tests/unit/test_email_intel.py::test_urlhaus_unknown_url` | passed | EML-09 | 0.1 |
| `tests/unit/test_email_intel.py::test_urlscan_malicious_verdict` | passed | EML-09 | 0.14 |
| `tests/unit/test_email_parser.py::test_attachment_limit` | passed | EML-01, EML-02, EML-03 | 0.13 |
| `tests/unit/test_email_parser.py::test_attachments_hashed_and_archive_listed` | passed | EML-01, EML-02, EML-03 | 0.04 |
| `tests/unit/test_email_parser.py::test_extract_urls_from_text_and_html` | passed | EML-01, EML-02, EML-03 | 0.0 |
| `tests/unit/test_email_parser.py::test_forwarded_original_is_analysed` | passed | EML-01, EML-02, EML-03 | 0.04 |
| `tests/unit/test_email_parser.py::test_garbage_input_is_handled` | passed | EML-01, EML-02, EML-03 | 0.0 |
| `tests/unit/test_email_parser.py::test_headers_and_sender` | passed | EML-01, EML-02, EML-03 | 0.06 |
| `tests/unit/test_email_parser.py::test_links_extracted_unwrapped_and_deobfuscated` | passed | EML-01, EML-02, EML-03 | 0.06 |
| `tests/unit/test_email_parser.py::test_malformed_mime_does_not_crash` | passed | EML-01, EML-02, EML-03 | 0.01 |
| `tests/unit/test_email_parser.py::test_unwrap[https://a.test/plain-https://a.test/plain]` | passed | EML-01, EML-02, EML-03 | 0.0 |
| `tests/unit/test_email_parser.py::test_unwrap[https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fa.test%2Fb&data=1-https://a.test/b]` | passed | EML-01, EML-02, EML-03 | 0.0 |
| `tests/unit/test_email_parser.py::test_unwrap[https://urldefense.proofpoint.com/v2/url?u=https-3A__a.test_d&d=x-https://a.test/d]` | passed | EML-01, EML-02, EML-03 | 0.0 |
| `tests/unit/test_email_parser.py::test_unwrap[https://www.google.com/url?q=https://a.test/c&sa=D-https://a.test/c]` | passed | EML-01, EML-02, EML-03 | 0.0 |
| `tests/unit/test_email_parser.py::test_unwrap[hxxp://a[.]test/e-http://a.test/e]` | passed | EML-01, EML-02, EML-03 | 0.0 |
| `tests/unit/test_email_posture.py::test_duplicate_dmarc_record_is_missing` | passed | EML-15, EML-16 | 0.0 |
| `tests/unit/test_email_posture.py::test_missing_spf_and_dmarc_is_high_risk` | passed | EML-15, EML-16 | 0.0 |
| `tests/unit/test_email_posture.py::test_softfail_spf_and_none_policy` | passed | EML-15, EML-16 | 0.0 |
| `tests/unit/test_email_posture.py::test_well_configured_domain_no_alert` | passed | EML-15, EML-16 | 0.0 |
| `tests/unit/test_email_scoring.py::test_email_modules_use_all_four_levels[dmarc]` | passed | EML-12 | 0.0 |
| `tests/unit/test_email_scoring.py::test_email_modules_use_all_four_levels[email]` | passed | EML-12 | 0.0 |
| `tests/unit/test_email_scoring.py::test_email_modules_use_all_four_levels[email_posture]` | passed | EML-12 | 0.0 |
| `tests/unit/test_email_scoring.py::test_email_rules[signals0-40-known_malicious_url]` | passed | EML-12 | 0.0 |
| `tests/unit/test_email_scoring.py::test_email_rules[signals1-15-single_source_url_hit]` | passed | EML-12 | 0.0 |
| `tests/unit/test_email_scoring.py::test_email_rules[signals10-10-bad_sender_ip]` | passed | EML-12 | 0.0 |
| `tests/unit/test_email_scoring.py::test_email_rules[signals11-10-rspamd_phish]` | passed | EML-12 | 0.0 |
| `tests/unit/test_email_scoring.py::test_email_rules[signals12-20-live_phishing_page]` | passed | EML-12 | 0.0 |
| `tests/unit/test_email_scoring.py::test_email_rules[signals13-10-lookalike_can_send]` | passed | EML-12 | 0.0 |
| `tests/unit/test_email_scoring.py::test_email_rules[signals14-40-posture_dmarc_missing]` | passed | EML-12 | 0.0 |
| `tests/unit/test_email_scoring.py::test_email_rules[signals15-20-posture_dmarc_none]` | passed | EML-12 | 0.0 |
| `tests/unit/test_email_scoring.py::test_email_rules[signals16-40-posture_spf_missing]` | passed | EML-12 | 0.0 |
| `tests/unit/test_email_scoring.py::test_email_rules[signals17-10-posture_spf_softfail]` | passed | EML-12 | 0.0 |
| `tests/unit/test_email_scoring.py::test_email_rules[signals18-10-posture_dkim_missing]` | passed | EML-12 | 0.0 |
| `tests/unit/test_email_scoring.py::test_email_rules[signals19-5-posture_mta_sts_missing]` | passed | EML-12 | 0.0 |
| `tests/unit/test_email_scoring.py::test_email_rules[signals2-40-malware_attachment]` | passed | EML-12 | 0.0 |
| `tests/unit/test_email_scoring.py::test_email_rules[signals3-20-suspicious_attachment]` | passed | EML-12 | 0.0 |
| `tests/unit/test_email_scoring.py::test_email_rules[signals4-30-auth_fail_brand_from]` | passed | EML-12 | 0.0 |
| `tests/unit/test_email_scoring.py::test_email_rules[signals5-25-lookalike_sender]` | passed | EML-12 | 0.0 |
| `tests/unit/test_email_scoring.py::test_email_rules[signals6-20-brand_impersonation]` | passed | EML-12 | 0.0 |
| `tests/unit/test_email_scoring.py::test_email_rules[signals7-10-reply_to_mismatch]` | passed | EML-12 | 0.0 |
| `tests/unit/test_email_scoring.py::test_email_rules[signals8-15-credential_or_payment_language]` | passed | EML-12 | 0.0 |
| `tests/unit/test_email_scoring.py::test_email_rules[signals9-10-young_domain]` | passed | EML-12 | 0.0 |
| `tests/unit/test_email_scoring.py::test_typical_phish_is_critical` | passed | EML-12 | 0.0 |
| `tests/unit/test_fetch.py::test_allowlisted_private_host` | passed | FND-12, FND-13 | 0.0 |
| `tests/unit/test_fetch.py::test_blocks_internal_destinations[http://127.0.0.1/]` | passed | FND-12, FND-13 | 0.0 |
| `tests/unit/test_fetch.py::test_blocks_internal_destinations[http://[::1]/]` | passed | FND-12, FND-13 | 0.0 |
| `tests/unit/test_fetch.py::test_blocks_internal_destinations[http://evil.test/]` | passed | FND-12, FND-13 | 0.0 |
| `tests/unit/test_fetch.py::test_blocks_internal_destinations[http://loop.test/]` | passed | FND-12, FND-13 | 0.0 |
| `tests/unit/test_fetch.py::test_blocks_internal_destinations[http://meta.test/latest/meta-data]` | passed | FND-12, FND-13 | 0.0 |
| `tests/unit/test_fetch.py::test_blocks_non_http_schemes[file:///etc/passwd]` | passed | FND-12, FND-13 | 0.0 |
| `tests/unit/test_fetch.py::test_blocks_non_http_schemes[ftp://example.com/x]` | passed | FND-12, FND-13 | 0.0 |
| `tests/unit/test_fetch.py::test_blocks_non_http_schemes[gopher://x]` | passed | FND-12, FND-13 | 0.0 |
| `tests/unit/test_fetch.py::test_follows_public_redirects` | passed | FND-12, FND-13 | 0.01 |
| `tests/unit/test_fetch.py::test_gives_up_after_retries` | passed | FND-12, FND-13 | 1.51 |
| `tests/unit/test_fetch.py::test_nat64_addresses_judged_by_embedded_ipv4[64:ff9b::14cc:f4c0-False]` | passed | FND-12, FND-13 | 0.0 |
| `tests/unit/test_fetch.py::test_nat64_addresses_judged_by_embedded_ipv4[64:ff9b::7f00:1-True]` | passed | FND-12, FND-13 | 0.0 |
| `tests/unit/test_fetch.py::test_nat64_addresses_judged_by_embedded_ipv4[64:ff9b::a00:5-True]` | passed | FND-12, FND-13 | 0.0 |
| `tests/unit/test_fetch.py::test_nat64_addresses_judged_by_embedded_ipv4[64:ff9b::a9fe:a9fe-True]` | passed | FND-12, FND-13 | 0.0 |
| `tests/unit/test_fetch.py::test_redirect_to_internal_host_is_blocked` | passed | FND-12, FND-13 | 0.01 |
| `tests/unit/test_fetch.py::test_retries_server_errors_then_succeeds` | passed | FND-12, FND-13 | 0.51 |
| `tests/unit/test_fetch.py::test_size_cap` | passed | FND-12, FND-13 | 0.0 |
| `tests/unit/test_lookalike_email.py::test_domain_with_mx_only_can_receive_not_send` | passed | EML-17 | 0.0 |
| `tests/unit/test_lookalike_email.py::test_domain_with_spf_can_send` | passed | EML-17 | 0.0 |
| `tests/unit/test_lookalike_email.py::test_unrelated_txt_is_not_spf` | passed | EML-17 | 0.0 |
| `tests/unit/test_no_test_data_in_product.py::test_brand_schemas_reject_demo_mode` | passed | RDA-01, RDA-04 | 0.0 |
| `tests/unit/test_no_test_data_in_product.py::test_product_code_has_no_demo_or_fixture_paths` | passed | RDA-01, RDA-04 | 1.39 |
| `tests/unit/test_no_test_data_in_product.py::test_settings_have_no_demo_switch` | passed | RDA-01, RDA-04 | 0.0 |
| `tests/unit/test_pagecheck.py::test_brand_name_on_page_is_brand_evidence` | passed | D-29, PHI-08 | 0.0 |
| `tests/unit/test_pagecheck.py::test_link_to_official_site_is_brand_evidence` | passed | D-29, PHI-08 | 0.0 |
| `tests/unit/test_pagecheck.py::test_official_email_domain_is_brand_evidence` | passed | D-29, PHI-08 | 0.0 |
| `tests/unit/test_pagecheck.py::test_ordinary_shop_mentioning_domains_is_not_parked` | passed | D-29, PHI-08 | 0.0 |
| `tests/unit/test_pagecheck.py::test_page_naming_its_own_lookalike_domain_is_not_brand_evidence` | passed | D-29, PHI-08 | 0.0 |
| `tests/unit/test_pagecheck.py::test_parked_pages_detected[https://example.com/lander-]` | passed | D-29, PHI-08 | 0.0 |
| `tests/unit/test_pagecheck.py::test_parked_pages_detected[https://sedo.com/search/details/?domain=x.com-]` | passed | D-29, PHI-08 | 0.0 |
| `tests/unit/test_pagecheck.py::test_parked_pages_detected[https://www.hugedomains.com/domain_profile.cfm?d=chitmart.com-Get this domain]` | passed | D-29, PHI-08 | 0.0 |
| `tests/unit/test_pagecheck.py::test_parked_pages_detected[https://x.com/-This domain is for sale! Buy this domain today.]` | passed | D-29, PHI-08 | 0.0 |
| `tests/unit/test_pagecheck.py::test_parked_pages_detected[https://x.com/-This domain may be for sale]` | passed | D-29, PHI-08 | 0.0 |
| `tests/unit/test_pagecheck.py::test_short_abbreviation_alone_is_not_brand_evidence` | passed | D-29, PHI-08 | 0.0 |
| `tests/unit/test_pagecheck.py::test_unrelated_business_with_login_has_no_brand_evidence` | passed | D-29, PHI-08 | 0.0 |
| `tests/unit/test_relevance.py::test_brand_uses_are_relevant[Chitkart Loans-Instant chit loans]` | passed | APK-03, D-25, DOC-04, ROG-04, SOC-06, SOC-07 | 0.0 |
| `tests/unit/test_relevance.py::test_brand_uses_are_relevant[Chitkartt-chit fund]` | passed | APK-03, D-25, DOC-04, ROG-04, SOC-06, SOC-07 | 0.0 |
| `tests/unit/test_relevance.py::test_brand_uses_are_relevant[KCPL Chits Helper-Pay your KCPL chit instalments]` | passed | APK-03, D-25, DOC-04, ROG-04, SOC-06, SOC-07 | 0.0 |
| `tests/unit/test_relevance.py::test_brand_uses_are_relevant[Kodachadri Chit Fund App-Kodachadri chits members]` | passed | APK-03, D-25, DOC-04, ROG-04, SOC-06, SOC-07 | 0.0 |
| `tests/unit/test_relevance.py::test_brand_uses_are_relevant[MyKCPL Pay-pay dues]` | passed | APK-03, D-25, DOC-04, ROG-04, SOC-06, SOC-07 | 0.0 |
| `tests/unit/test_relevance.py::test_term_strength` | passed | APK-03, D-25, DOC-04, ROG-04, SOC-06, SOC-07 | 0.0 |
| `tests/unit/test_relevance.py::test_unrelated_acronym_collisions_are_not_relevant[KCL - Kerala Cricket League-Official app of the Kerala Cricket League]` | passed | APK-03, D-25, DOC-04, ROG-04, SOC-06, SOC-07 | 0.0 |
| `tests/unit/test_relevance.py::test_unrelated_acronym_collisions_are_not_relevant[KCPL Service & IOT-Kirloskar KCPL service management]` | passed | APK-03, D-25, DOC-04, ROG-04, SOC-06, SOC-07 | 0.0 |
| `tests/unit/test_relevance.py::test_unrelated_acronym_collisions_are_not_relevant[Kanawha County Public Library-Kanawha County Public Library app. KCPL card holders]` | passed | APK-03, D-25, DOC-04, ROG-04, SOC-06, SOC-07 | 0.0 |
| `tests/unit/test_relevance.py::test_unrelated_acronym_collisions_are_not_relevant[MyKPL-Solus UK loyalty app]` | passed | APK-03, D-25, DOC-04, ROG-04, SOC-06, SOC-07 | 0.0 |
| `tests/unit/test_relevance.py::test_unrelated_acronym_collisions_are_not_relevant[RKCPL-Veenus software ERP]` | passed | APK-03, D-25, DOC-04, ROG-04, SOC-06, SOC-07 | 0.0 |
| `tests/unit/test_relevance.py::test_zentrova_demo_brand_unchanged` | passed | APK-03, D-25, DOC-04, ROG-04, SOC-06, SOC-07 | 0.0 |
| `tests/unit/test_rogue_app_stores.py::test_play_details_scam_checks_and_apple_store` | passed | ROG-01, ROG-02, ROG-03, ROG-04 | 0.01 |
| `tests/unit/test_runner_reporting.py::test_apk_keeps_results_of_searches_that_worked` | passed | RDA-03, RDA-17, RDA-21 | 0.0 |
| `tests/unit/test_runner_reporting.py::test_apk_scan_fails_when_every_search_is_unavailable` | passed | RDA-03, RDA-17, RDA-21 | 0.0 |
| `tests/unit/test_runner_reporting.py::test_apk_store_search_keeps_scan_alive_when_web_search_is_down` | passed | RDA-03, RDA-17, RDA-21 | 0.0 |
| `tests/unit/test_runner_reporting.py::test_blocked_telegram_pages_are_not_reported_as_not_found` | passed | RDA-03, RDA-17, RDA-21 | 0.0 |
| `tests/unit/test_runner_reporting.py::test_documents_scan_fails_when_every_search_is_unavailable` | passed | RDA-03, RDA-17, RDA-21 | 0.0 |
| `tests/unit/test_runner_reporting.py::test_logo_fails_when_no_target_page_could_be_captured` | passed | RDA-03, RDA-17, RDA-21 | 0.0 |
| `tests/unit/test_runner_reporting.py::test_logo_without_official_logo_is_not_configured_and_fails` | passed | RDA-03, RDA-17, RDA-21 | 0.0 |
| `tests/unit/test_runner_reporting.py::test_rogue_app_fails_when_every_store_search_fails` | passed | RDA-03, RDA-17, RDA-21 | 0.06 |
| `tests/unit/test_runner_reporting.py::test_social_with_every_source_down_fails` | passed | RDA-03, RDA-17, RDA-21 | 0.0 |
| `tests/unit/test_runner_reporting.py::test_social_without_telegram_credentials_is_not_configured` | passed | RDA-03, RDA-17, RDA-21 | 0.0 |
| `tests/unit/test_runner_reporting.py::test_txt_nxdomain_is_a_definitive_empty_answer` | passed | RDA-03, RDA-17, RDA-21 | 0.0 |
| `tests/unit/test_runner_reporting.py::test_txt_timeout_is_unknown_not_missing` | passed | RDA-03, RDA-17, RDA-21 | 0.0 |
| `tests/unit/test_runner_reporting.py::test_unconfigured_search_is_not_configured_not_unavailable` | passed | RDA-03, RDA-17, RDA-21 | 0.0 |
| `tests/unit/test_scan_report.py::test_all_ok_is_completed` | passed | RDA-03, RDA-17, RDA-21 | 0.0 |
| `tests/unit/test_scan_report.py::test_components_keep_insertion_order` | passed | RDA-03, RDA-17, RDA-21 | 0.0 |
| `tests/unit/test_scan_report.py::test_crash_fails_run` | passed | RDA-03, RDA-17, RDA-21 | 0.0 |
| `tests/unit/test_scan_report.py::test_errors_lists_failed_and_unavailable_messages` | passed | RDA-03, RDA-17, RDA-21 | 0.0 |
| `tests/unit/test_scan_report.py::test_failure_beats_reduced_coverage` | passed | RDA-03, RDA-17, RDA-21 | 0.0 |
| `tests/unit/test_scan_report.py::test_fatal_component_fails_run` | passed | RDA-03, RDA-17, RDA-21 | 0.0 |
| `tests/unit/test_scan_report.py::test_fatal_unavailable_fails_run` | passed | RDA-03, RDA-17, RDA-21 | 0.0 |
| `tests/unit/test_scan_report.py::test_no_components_is_completed` | passed | RDA-03, RDA-17, RDA-21 | 0.0 |
| `tests/unit/test_scan_report.py::test_not_configured_is_partially_completed` | passed | RDA-03, RDA-17, RDA-21 | 0.0 |
| `tests/unit/test_scan_report.py::test_repeated_component_keeps_worst_status_and_sums_counts` | passed | RDA-03, RDA-17, RDA-21 | 0.0 |
| `tests/unit/test_scan_report.py::test_skipped_alone_is_completed` | passed | RDA-03, RDA-17, RDA-21 | 0.0 |
| `tests/unit/test_scan_report.py::test_unavailable_is_partially_completed` | passed | RDA-03, RDA-17, RDA-21 | 0.0 |
| `tests/unit/test_scoring.py::test_cap_boundaries_do_not_raise_low_scores` | passed | D-29, OUT-02, RSK-01, RSK-02, RSK-03, RSK-04, RSK-05, RSK-06, RSK-07, RSK-08, RSK-09, RSK-10 | 0.0 |
| `tests/unit/test_scoring.py::test_cap_reason_reported_in_alert_signals` | passed | D-29, OUT-02, RSK-01, RSK-02, RSK-03, RSK-04, RSK-05, RSK-06, RSK-07, RSK-08, RSK-09, RSK-10 | 0.0 |
| `tests/unit/test_scoring.py::test_clamped_score_stays_consistent_with_level` | passed | OUT-02, RSK-01, RSK-02, RSK-03, RSK-04, RSK-05, RSK-06, RSK-07, RSK-08, RSK-09, RSK-10 | 0.0 |
| `tests/unit/test_scoring.py::test_domain_without_website_is_not_capped` | passed | D-29, OUT-02, RSK-01, RSK-02, RSK-03, RSK-04, RSK-05, RSK-06, RSK-07, RSK-08, RSK-09, RSK-10 | 0.0 |
| `tests/unit/test_scoring.py::test_each_rule_adds_its_points[signals0-40-brand_exact_in_domain]` | passed | OUT-02, RSK-01, RSK-02, RSK-03, RSK-04, RSK-05, RSK-06, RSK-07, RSK-08, RSK-09, RSK-10 | 0.0 |
| `tests/unit/test_scoring.py::test_each_rule_adds_its_points[signals1-25-typo_similarity_gt_80]` | passed | OUT-02, RSK-01, RSK-02, RSK-03, RSK-04, RSK-05, RSK-06, RSK-07, RSK-08, RSK-09, RSK-10 | 0.0 |
| `tests/unit/test_scoring.py::test_each_rule_adds_its_points[signals10-30-doc_sensitive_pattern]` | passed | OUT-02, RSK-01, RSK-02, RSK-03, RSK-04, RSK-05, RSK-06, RSK-07, RSK-08, RSK-09, RSK-10 | 0.0 |
| `tests/unit/test_scoring.py::test_each_rule_adds_its_points[signals11-20-doc_many_emails]` | passed | OUT-02, RSK-01, RSK-02, RSK-03, RSK-04, RSK-05, RSK-06, RSK-07, RSK-08, RSK-09, RSK-10 | 0.0 |
| `tests/unit/test_scoring.py::test_each_rule_adds_its_points[signals2-15-mx_present]` | passed | OUT-02, RSK-01, RSK-02, RSK-03, RSK-04, RSK-05, RSK-06, RSK-07, RSK-08, RSK-09, RSK-10 | 0.0 |
| `tests/unit/test_scoring.py::test_each_rule_adds_its_points[signals3-10-https]` | passed | OUT-02, RSK-01, RSK-02, RSK-03, RSK-04, RSK-05, RSK-06, RSK-07, RSK-08, RSK-09, RSK-10 | 0.0 |
| `tests/unit/test_scoring.py::test_each_rule_adds_its_points[signals4-20-login_payment_keywords]` | passed | OUT-02, RSK-01, RSK-02, RSK-03, RSK-04, RSK-05, RSK-06, RSK-07, RSK-08, RSK-09, RSK-10 | 0.0 |
| `tests/unit/test_scoring.py::test_each_rule_adds_its_points[signals5-30-official_logo]` | passed | OUT-02, RSK-01, RSK-02, RSK-03, RSK-04, RSK-05, RSK-06, RSK-07, RSK-08, RSK-09, RSK-10 | 0.0 |
| `tests/unit/test_scoring.py::test_each_rule_adds_its_points[signals6-20-social_image_match]` | passed | OUT-02, RSK-01, RSK-02, RSK-03, RSK-04, RSK-05, RSK-06, RSK-07, RSK-08, RSK-09, RSK-10 | 0.0 |
| `tests/unit/test_scoring.py::test_each_rule_adds_its_points[signals7-25-publisher_mismatch]` | passed | OUT-02, RSK-01, RSK-02, RSK-03, RSK-04, RSK-05, RSK-06, RSK-07, RSK-08, RSK-09, RSK-10 | 0.0 |
| `tests/unit/test_scoring.py::test_each_rule_adds_its_points[signals8-30-doc_brand_keyword]` | passed | OUT-02, RSK-01, RSK-02, RSK-03, RSK-04, RSK-05, RSK-06, RSK-07, RSK-08, RSK-09, RSK-10 | 0.0 |
| `tests/unit/test_scoring.py::test_each_rule_adds_its_points[signals9-20-doc_official_domain]` | passed | OUT-02, RSK-01, RSK-02, RSK-03, RSK-04, RSK-05, RSK-06, RSK-07, RSK-08, RSK-09, RSK-10 | 0.0 |
| `tests/unit/test_scoring.py::test_level_boundaries[0-Low]` | passed | OUT-02, RSK-01, RSK-02, RSK-03, RSK-04, RSK-05, RSK-06, RSK-07, RSK-08, RSK-09, RSK-10 | 0.0 |
| `tests/unit/test_scoring.py::test_level_boundaries[100-Critical]` | passed | OUT-02, RSK-01, RSK-02, RSK-03, RSK-04, RSK-05, RSK-06, RSK-07, RSK-08, RSK-09, RSK-10 | 0.0 |
| `tests/unit/test_scoring.py::test_level_boundaries[29-Low]` | passed | OUT-02, RSK-01, RSK-02, RSK-03, RSK-04, RSK-05, RSK-06, RSK-07, RSK-08, RSK-09, RSK-10 | 0.0 |
| `tests/unit/test_scoring.py::test_level_boundaries[30-Medium]` | passed | OUT-02, RSK-01, RSK-02, RSK-03, RSK-04, RSK-05, RSK-06, RSK-07, RSK-08, RSK-09, RSK-10 | 0.0 |
| `tests/unit/test_scoring.py::test_level_boundaries[59-Medium]` | passed | OUT-02, RSK-01, RSK-02, RSK-03, RSK-04, RSK-05, RSK-06, RSK-07, RSK-08, RSK-09, RSK-10 | 0.0 |
| `tests/unit/test_scoring.py::test_level_boundaries[60-High]` | passed | OUT-02, RSK-01, RSK-02, RSK-03, RSK-04, RSK-05, RSK-06, RSK-07, RSK-08, RSK-09, RSK-10 | 0.0 |
| `tests/unit/test_scoring.py::test_level_boundaries[79-High]` | passed | OUT-02, RSK-01, RSK-02, RSK-03, RSK-04, RSK-05, RSK-06, RSK-07, RSK-08, RSK-09, RSK-10 | 0.0 |
| `tests/unit/test_scoring.py::test_level_boundaries[80-Critical]` | passed | OUT-02, RSK-01, RSK-02, RSK-03, RSK-04, RSK-05, RSK-06, RSK-07, RSK-08, RSK-09, RSK-10 | 0.0 |
| `tests/unit/test_scoring.py::test_live_site_with_brand_evidence_can_be_critical` | passed | D-29, OUT-02, RSK-01, RSK-02, RSK-03, RSK-04, RSK-05, RSK-06, RSK-07, RSK-08, RSK-09, RSK-10 | 0.0 |
| `tests/unit/test_scoring.py::test_live_site_without_brand_evidence_capped_at_medium` | passed | D-29, OUT-02, RSK-01, RSK-02, RSK-03, RSK-04, RSK-05, RSK-06, RSK-07, RSK-08, RSK-09, RSK-10 | 0.0 |
| `tests/unit/test_scoring.py::test_module_level_clamp[apk-raw_points_signals0-Medium]` | passed | OUT-02, RSK-01, RSK-02, RSK-03, RSK-04, RSK-05, RSK-06, RSK-07, RSK-08, RSK-09, RSK-10 | 0.0 |
| `tests/unit/test_scoring.py::test_module_level_clamp[apk-raw_points_signals1-High]` | passed | OUT-02, RSK-01, RSK-02, RSK-03, RSK-04, RSK-05, RSK-06, RSK-07, RSK-08, RSK-09, RSK-10 | 0.0 |
| `tests/unit/test_scoring.py::test_module_level_clamp[documents-raw_points_signals6-Medium]` | passed | OUT-02, RSK-01, RSK-02, RSK-03, RSK-04, RSK-05, RSK-06, RSK-07, RSK-08, RSK-09, RSK-10 | 0.0 |
| `tests/unit/test_scoring.py::test_module_level_clamp[documents-raw_points_signals7-Critical]` | passed | OUT-02, RSK-01, RSK-02, RSK-03, RSK-04, RSK-05, RSK-06, RSK-07, RSK-08, RSK-09, RSK-10 | 0.0 |
| `tests/unit/test_scoring.py::test_module_level_clamp[logo-raw_points_signals3-High]` | passed | OUT-02, RSK-01, RSK-02, RSK-03, RSK-04, RSK-05, RSK-06, RSK-07, RSK-08, RSK-09, RSK-10 | 0.0 |
| `tests/unit/test_scoring.py::test_module_level_clamp[rogue_app-raw_points_signals2-Medium]` | passed | OUT-02, RSK-01, RSK-02, RSK-03, RSK-04, RSK-05, RSK-06, RSK-07, RSK-08, RSK-09, RSK-10 | 0.0 |
| `tests/unit/test_scoring.py::test_module_level_clamp[social-raw_points_signals4-Low]` | passed | OUT-02, RSK-01, RSK-02, RSK-03, RSK-04, RSK-05, RSK-06, RSK-07, RSK-08, RSK-09, RSK-10 | 0.0 |
| `tests/unit/test_scoring.py::test_module_level_clamp[social-raw_points_signals5-High]` | passed | OUT-02, RSK-01, RSK-02, RSK-03, RSK-04, RSK-05, RSK-06, RSK-07, RSK-08, RSK-09, RSK-10 | 0.0 |
| `tests/unit/test_scoring.py::test_module_level_clamp[typosquat-raw_points_signals8-Low]` | passed | OUT-02, RSK-01, RSK-02, RSK-03, RSK-04, RSK-05, RSK-06, RSK-07, RSK-08, RSK-09, RSK-10 | 0.0 |
| `tests/unit/test_scoring.py::test_no_signals_scores_zero_low` | passed | OUT-02, RSK-01, RSK-02, RSK-03, RSK-04, RSK-05, RSK-06, RSK-07, RSK-08, RSK-09, RSK-10 | 0.0 |
| `tests/unit/test_scoring.py::test_parked_page_capped_at_low_even_with_brand_text` | passed | D-29, OUT-02, RSK-01, RSK-02, RSK-03, RSK-04, RSK-05, RSK-06, RSK-07, RSK-08, RSK-09, RSK-10 | 0.0 |
| `tests/unit/test_scoring.py::test_production_refuses_default_secrets` | passed | FND-15, OUT-02, RSK-01, RSK-02, RSK-03, RSK-04, RSK-05, RSK-06, RSK-07, RSK-08, RSK-09, RSK-10 | 0.02 |
| `tests/unit/test_scoring.py::test_production_refuses_test_website_allowlist` | passed | D-27, OUT-02, RSK-01, RSK-02, RSK-03, RSK-04, RSK-05, RSK-06, RSK-07, RSK-08, RSK-09, RSK-10 | 0.01 |
| `tests/unit/test_scoring.py::test_rules_stack` | passed | OUT-02, RSK-01, RSK-02, RSK-03, RSK-04, RSK-05, RSK-06, RSK-07, RSK-08, RSK-09, RSK-10 | 0.0 |
| `tests/unit/test_scoring.py::test_score_capped_at_100` | passed | OUT-02, RSK-01, RSK-02, RSK-03, RSK-04, RSK-05, RSK-06, RSK-07, RSK-08, RSK-09, RSK-10 | 0.0 |
| `tests/unit/test_scoring.py::test_typo_similarity_exactly_80_does_not_score` | passed | OUT-02, RSK-01, RSK-02, RSK-03, RSK-04, RSK-05, RSK-06, RSK-07, RSK-08, RSK-09, RSK-10 | 0.0 |
| `tests/unit/test_similarity.py::test_brand_terms_in_text` | passed | APK-03, APK-04, SOC-06, SOC-07, TYP-13 | 0.0 |
| `tests/unit/test_similarity.py::test_domain_label_uses_registered_domain` | passed | APK-03, APK-04, SOC-06, SOC-07, TYP-13 | 0.0 |
| `tests/unit/test_similarity.py::test_fold_homoglyphs_cyrillic_and_digits` | passed | APK-03, APK-04, SOC-06, SOC-07, TYP-13 | 0.0 |
| `tests/unit/test_similarity.py::test_idn_decoded` | passed | APK-03, APK-04, SOC-06, SOC-07, TYP-13 | 0.0 |
| `tests/unit/test_similarity.py::test_similar_names_score_high[z\u0435ntrova-100]` | passed | APK-03, APK-04, SOC-06, SOC-07, TYP-13 | 0.0 |
| `tests/unit/test_similarity.py::test_similar_names_score_high[zentorva-80]` | passed | APK-03, APK-04, SOC-06, SOC-07, TYP-13 | 0.0 |
| `tests/unit/test_similarity.py::test_similar_names_score_high[zentova-85]` | passed | APK-03, APK-04, SOC-06, SOC-07, TYP-13 | 0.0 |
| `tests/unit/test_similarity.py::test_similar_names_score_high[zentr0va-100]` | passed | APK-03, APK-04, SOC-06, SOC-07, TYP-13 | 0.0 |
| `tests/unit/test_similarity.py::test_similar_names_score_high[zentrova-100]` | passed | APK-03, APK-04, SOC-06, SOC-07, TYP-13 | 0.0 |
| `tests/unit/test_similarity.py::test_similar_names_score_high[zentrova-login-100]` | passed | APK-03, APK-04, SOC-06, SOC-07, TYP-13 | 0.0 |
| `tests/unit/test_similarity.py::test_similarity_bounds` | passed | APK-03, APK-04, SOC-06, SOC-07, TYP-13 | 0.0 |
| `tests/unit/test_similarity.py::test_unrelated_names_score_low` | passed | APK-03, APK-04, SOC-06, SOC-07, TYP-13 | 0.0 |
| `tests/unit/test_tasks.py::test_follow_up_queued_after_scan` | passed | FND-07, LOGO-01 | 0.0 |
| `tests/unit/test_tasks.py::test_logo_alone_runs_immediately` | passed | FND-07, LOGO-01 | 0.0 |
| `tests/unit/test_tasks.py::test_logo_follows_domain_scan` | passed | FND-07, LOGO-01 | 0.0 |

## 4. Manual UAT checklist (analyst sign-off)

Run through `docs/demo/DEMO-GUIDE.md` and tick each item.

| # | Check | Tester | Date | Result |
|---|---|---|---|---|
| 1 | Log in as analyst; dashboard tiles and charts show today's numbers | | | |
| 2 | Add a new brand with logo, favicon, domains, packages, publishers, handles | | | |
| 3 | Run a scan; scan appears in Scans with statistics | | | |
| 4 | Alert queue filters (brand, module, risk, status, dates, search) give expected rows | | | |
| 5 | Open a phishing alert: screenshot, SSL, WHOIS, favicon evidence visible | | | |
| 6 | Move an alert New → Under Review → Confirmed → Closed with notes; history shows each step | | | |
| 7 | Mark a look-alike as False Positive | | | |
| 8 | Export CSV and PDF with filters applied | | | |
| 9 | Admin creates an analyst user; analyst cannot edit brands | | | |
| 10 | Layout usable on a phone and a tablet | | | |
