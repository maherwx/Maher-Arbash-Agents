# Maher-Vuln-Research

حزمة CLI محلية لأبحاث الثغرات وبرامج Bug Bounty ضمن النطاق المصرح به.

## البنية الحالية

- Orchestrator لوكلاء البحث المتخصصين.
- تحليل Traffic لـ HAR / Burp / ZAP مع behavioral modeling وprotocol intelligence وworkflow correlation.
- Unified IR متعدد اللغات مع call graph وinterprocedural data-flow.
- Semantic resolution للاستدعاءات الغامضة مع confidence/margin وfail-closed عند عدم كفاية الدليل.
- Static ↔ Runtime Fusion لربط routes والدوال وتدفق البيانات بإشارات التشغيل المرصودة.
- Evidence correlation/fusion وprovenance وquality gates.
- Benchmark corpus من 126 حالة تشمل positive/negative/adversarial/workflow/stress/noise.
- Regression determinism وquality-history وcapability scorecard.
- Performance/memory guard واختبار CI لمشروع اصطناعي كبير.
- Input hardening ضد duplicate IDs وmalformed shapes والأحجام غير المعقولة.
- Release readiness gate موحد يفشل عند تراجع benchmark أو coverage أو capability floor.

## خط التحليل المتقدم

`Analyzer IR → Unified IR → Semantic Resolution → Interprocedural Flow → Coverage Gate → Static/Runtime Fusion → Evidence`

تعمل اختبارات Python تلقائيًا في GitHub Actions، إضافة إلى فحوص Rust وGo وTypeScript وruntime smoke للأنظمة الأخرى.

- تشغيل Windows أو Linux/Kali.
- لا يحتاج API سحابي.
- ملف `scope.yaml` يحدد النطاق المصرح به.

## تشغيل الفحوص النشطة ضمن التفويض

ملف المثال يفعّل الفحوص النشطة ضمن النطاق المحدد. شغّلها صراحةً مع تأكيد التفويض:

```bash
maher-bounty run --scope examples/scope.yaml --rules examples/rules.yaml --authorized
maher-bounty auto-run --target <authorized-target> --authorized
```

إذا لم تُفعّل `allow_active_discovery`، يوضح التقرير أن الفحص النشط تم تخطيه؛ الجرد والفرضيات وحدهما لا يمثلان نتائج ثغرات مؤكدة.
