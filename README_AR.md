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


## أدوات تحليل حركة متقدمة داخل المشروع

عند استخدام `traffic-analyze` أو تمرير `--traffic` إلى `auto-run`، يشغّل النظام خمس وحدات داخلية على سجلات المرور المصرح بها:

1. **Request Surface Mapper**: تجميع المسارات وطرق HTTP وأسماء المعاملات مع تطبيع معرّفات المسارات.
2. **Auth Boundary Differential**: مقارنة الاستجابات المرصودة بين الطلبات ذات بيانات الاعتماد والطلبات التي لا تظهر فيها بيانات اعتماد، وإنتاج مؤشرات للمراجعة فقط.
3. **Response Security Posture**: مراجعة ترويسات الأمان وخصائص الكوكيز وإعدادات CORS المرصودة.
4. **Parameter Behavior Correlator**: ربط أسماء المعاملات باختلاف أشكال الاستجابات المرصودة؛ لا يرسل حمولات اختبارية.
5. **Workflow Transition Miner**: استخراج تسلسل المسارات والحالات من المرور المحفوظ دون نشر قيم الجلسات.

تُحفظ النتائج في `advanced-web-tools.json` أثناء `traffic-analyze`، أو `advanced-traffic-tools.json` عند تمرير مرور إلى `run` أو `auto-run`. تعمل هذه الوحدات على المرور المسجل؛ وهي ليست واجهة اعتراض حية لطلبات المتصفح مثل Burp Proxy.

زِيدت مهلة التنفيذ لكل أداة محلية 180 ثانية فوق مهلة الأساس الخاصة بها. تظل المهلة محددة لكل عملية، وتُسجّل حالة الانتهاء أو انتهاء المهلة كي لا تبقى العملية معلّقة إلى الأبد.


## تشغيل الوكلاء محليًا دون خدمة نموذج سحابية

لا يحتاج منسق الأدوات إلى نموذج أو API خارجي كي ينفذ المتابعات. عند تفعيل الفحص المصرح به، يبني منسق محلي حتمي خطة للأدوات غير المغطاة بنجاح، ثم يشغلها بالوسائط الثابتة على العناوين المعروفة داخل النطاق. إذا ضُبط نموذج مساعد، يقبل البرنامج عنوان loopback فقط مثل `127.0.0.1` أو `localhost`؛ تُرفض عناوين النماذج البعيدة. راجع `active/agent-followups.json` لمعرفة وضع المنسق، وطلبات الأدوات، والتغطية المعاد استخدامها، وحالات التشغيل.
