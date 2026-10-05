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
maher-bounty run --scope /path/to/your-program-scope.yaml --rules examples/rules.yaml --authorized
maher-bounty auto-run --target "app.in-scope-domain.test" --authorized
```

إذا لم يذكر ملف القواعد `allow_active_discovery`، فإن `--authorized` يفعّل الفحوص؛ أما القيمة `false` الصريحة فتخطيها ويظهر ذلك في التقرير. الجرد والفرضيات وحدهما لا يمثلان نتائج ثغرات مؤكدة.

## تشغيل الأدوات بتنسيق الوكلاء وبيانات Burp

يختار الوكلاء أدوات الفحص المحلية من قائمة ثابتة حسب الدليل المتوفر: Subfinder وAssetfinder وWaybackurls وgau وDNSX وAlterX وhttpx وHakrawler وKatana وNuclei وDalfox وZAP Baseline وNikto وNmap وNaabu وTLSX وWhatWeb وWAFW00F وFFUF وGobuster. يجري تنسيق الأداة على الرابط الموجود حرفيًا في النطاق، وتُصفّى المضيفات والمسارات الجديدة قبل تمريرها للمرحلة التالية. تُعاد الاستفادة من تغطية الفحص الأساسي كي لا تتكرر الأداة على الأصل أو المضيف نفسه. أدوات تحليل المصدر تعمل عند توفير مستودع المصدر، وBurp يدخل عبر XML/HAR. تُشغّل الأدوات بوسائط محددة من التطبيق؛ لا ينفذ النموذج نص shell حرًا.

يمكن تمرير تصدير حركة Burp XML أو HAR إلى الوكلاء بعد تصفيته حسب النطاق وإزالة قيم الترويسات السرية من ملخص الدليل:

```bash
maher-bounty auto-run --target "app.in-scope-domain.test" --authorized --traffic /path/to/burp-export.xml
```

يدعم الخيار أيضًا ملفات HAR، ويُحفظ ملخص الحركة ضمن حزمة التقرير. تبقى ملفات Burp الأصلية خارج ملخص النموذج.
