# RAGLOX v3.0 - Backend Integration TODO

## Phase 1: تحليل Backend API
- [ ] فحص API Documentation على http://172.245.232.188:8000/docs
- [ ] توثيق جميع الـ Endpoints المتاحة
- [ ] فهم هيكل البيانات (Data Models)

## Phase 2: Mission Data Integration
- [ ] إنشاء API client للتواصل مع Backend
- [ ] تحميل بيانات المهمة (Mission)
- [ ] تحميل Targets
- [ ] تحميل Vulnerabilities
- [ ] تحميل Credentials
- [ ] تحميل Sessions

## Phase 3: WebSocket Integration
- [ ] إنشاء WebSocket connection
- [ ] معالجة الأحداث الواردة
- [ ] إعادة الاتصال التلقائي
- [ ] تحديث حالة الاتصال (Live/Offline)

## Phase 4: User Messages Integration
- [ ] إرسال رسائل المستخدم للـ Backend
- [ ] استقبال ردود المساعد
- [ ] عرض الرسائل في الدردشة
- [ ] معالجة حالات الخطأ

## Phase 5: Dynamic Events Integration
- [ ] استلام الأحداث من Backend
- [ ] تحديث Event Cards ديناميكياً
- [ ] تحديث Knowledge من Backend
- [ ] تحديث Plan Tasks

## Phase 6: Terminal Integration
- [ ] عرض مخرجات الطرفية الحقيقية
- [ ] تنفيذ الأوامر الفعلية
- [ ] تحديث الطرفية في الوقت الفعلي

## Phase 7: Welcome Screen
- [ ] تحسين شاشة الترحيب
- [ ] ربط أزرار الإجراءات السريعة بالـ Backend
- [ ] Start Recon
- [ ] Scan Vulns
- [ ] Get Shell
- [ ] Auto Mode

## Phase 8: Testing
- [ ] اختبار تحميل البيانات
- [ ] اختبار WebSocket
- [ ] اختبار إرسال الرسائل
- [ ] اختبار الأحداث
- [ ] اختبار الطرفية

---

**Mission ID للاختبار:** `6b14028c-7f30-4ce6-aad2-20f17eee39d0`
**Backend URL:** `http://172.245.232.188:8000`
**Frontend URL:** `http://172.245.232.188:3000`
