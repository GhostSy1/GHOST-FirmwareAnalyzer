# GHOST-FirmwareAnalyzer TODO

- [x] تدقيق المستودع الحالي وتوثيق الفجوات المعمارية والوظيفية
- [x] تصميم بنية مستقلة متعددة الوحدات مع CLI واضح
- [x] تنفيذ تحليل SHA-256 والحجم وميتا-بيانات الملف دون بيانات ثابتة
- [x] تنفيذ تحليل entropy وmagic bytes وfile signatures للملفات الفعلية
- [x] تنفيذ استخراج strings مع إخفاء القيم الحساسة من التقرير
- [x] تنفيذ كشف مؤشرات الخدمات والملفات الحساسة داخل firmware
- [x] تنفيذ اكتشاف مؤشرات بروتوكولات التواصل من المحتوى الفعلي
- [x] تنفيذ تحليل ملفات rootfs المستخرجة عند توفرها دون تشغيلها
- [x] إضافة كشف استدلالي لمؤشرات backdoor مع تصنيف evidence وconfidence وحدود واضحة
- [x] إضافة نمط تحليل static-only ومنع تشغيل أي محتوى مستخرج
- [x] إضافة تقارير JSON وSARIF وCSV مع provenance وintegrity hash
- [x] إضافة سجل تدقيق محلي append-only لمخرجات التحليل
- [x] إضافة اختبارات وحدات وتكامل على ملفات حقيقية آمنة منشأة من أدوات النظام لا من نتائج مزيفة
- [x] إضافة GitHub Actions للجودة والاختبارات وفحص الأسرار
- [x] كتابة README شامل ومرجع CLI ودليل منهجية التحليل
- [x] إضافة توثيق معماري ورسوم Mermaid ودليل حدود الكشف
- [ ] تشغيل التحقق المحلي ومراجعة النتائج والأخطاء
- [ ] رفع الإصدار الكامل إلى GitHub وتوثيق ما تم التحقق منه فعلياً

## Professional Feature Expansion Backlog

- [x] Add domain-specific validation rules and robust error boundaries
- [x] Implement extensible report exporters (JSON, CSV, SARIF 2.1.0)
- [ ] Incorporate append-only evidence hashing and provenance tracking
- [x] Expand unit test coverage with realistic fixture inputs
- [ ] Add structured remediation guidance and severity-based triage scoring
- [ ] Launch without arguments and prompt for required target input
- [ ] Prompt for report paths with sensible defaults
- [ ] Keep --help concise and preserve non-interactive execution
- [ ] Keep README and CLI reference aligned with the actual prompts
- [ ] Add an interactive execution check
- [ ] Remove code comments from files changed in this pass
