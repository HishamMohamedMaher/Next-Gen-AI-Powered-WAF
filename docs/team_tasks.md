# توزيعة المهام على التيم — AI-WAF

> [!IMPORTANT]
> **قاعدة عامة:** كل عضو يبدأ يومه بـ **45 دقيقة مذاكرة** للحاجة اللي هيشتغل عليها النهارده. مش عيب تتعلم — العيب تضيع 4 ساعات لأنك ما بحثتش قبلها.

---

## 👤 تعريف الأعضاء

| الرمز | الدور | الوصف |
|---|---|---|
| **أ** | Tech Lead | الأقوى تقنياً — مسؤول الدمج والمراجعة |
| **ب** | Security Dev | الـ Normalizer والـ Signatures |
| **ج** | ML Engineer | البيانات والتدريب والموديلات |
| **د** | Backend Dev | الإعدادات والخدمات الخلفية |
| **هـ** | QA + Frontend | الاختبارات والـ Dashboard |

---

# الأسبوع الأول: Foundation (12–19 أكتوبر)

---

## 👤 عضو أ — Tech Lead

### يوم 1 (الاثنين 12/10): `waf/main.py` + `waf/proxy.py` — الهيكل

**المطلوب:**
- إنشاء `waf/main.py` — FastAPI app مع `lifespan` و catch-all route
- إنشاء `waf/proxy.py` — `init_client()` و `forward()` و `close_client()`
- الـ WAF يستقبل طلب على 8080 ويمرره لـ Juice Shop على 3000 ويرجّع الرد

**لازم تكون عارف:**
1. إزاي FastAPI بتشتغل (routes, Request object, Response object)
2. إيه الـ `lifespan` context manager في FastAPI (بديل `on_startup`)
3. إزاي `httpx.AsyncClient` بيعمل HTTP requests بـ connection pooling
4. إيه الـ Hop-by-Hop headers وليه بنحذفها (Connection, Keep-Alive, Transfer-Encoding, etc.)
5. إيه الفرق بين `async` و `sync` في Python

**يذاكر منين:**
- 📺 [FastAPI Tutorial - YouTube (بالعربي)](https://www.youtube.com/results?search_query=FastAPI+tutorial+arabic) — أول 30 دقيقة كفاية
- 📖 [FastAPI Official - First Steps](https://fastapi.tiangolo.com/tutorial/first-steps/) — أول 3 صفحات
- 📖 [FastAPI Lifespan](https://fastapi.tiangolo.com/advanced/events/#lifespan) — صفحة واحدة
- 📖 [httpx Async Client](https://www.python-httpx.org/async/) — قسم الـ async
- 📖 [Hop-by-Hop Headers - MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Connection)

---

### يوم 2 (الثلاثاء 13/10): `waf/proxy.py` — إكمال + `waf/context.py`

**المطلوب:**
- إكمال `proxy.py`: حذف Hop-by-Hop headers، إضافة `X-Forwarded-For`، حد حجم Body (1MB)، رد 502 لو Backend وقع
- إنشاء `waf/context.py` — `build_context()` اللي يقرأ الطلب ويطلّع `RequestContext`
- تحليل JSON body و form-urlencoded body

**لازم تكون عارف:**
1. إزاي تقرأ `request.body()` في FastAPI
2. الفرق بين `application/json` و `application/x-www-form-urlencoded`
3. إزاي `json.loads()` بتشتغل و إيه يحصل لو الـ JSON مش valid
4. إزاي `urllib.parse.parse_qs()` بتفكك form data
5. إيه `request.client.host` وإزاي تاخد IP العميل

**يذاكر منين:**
- 📖 [FastAPI Request Body](https://fastapi.tiangolo.com/tutorial/body/)
- 📖 [Python json module](https://docs.python.org/3/library/json.html) — `json.loads` بس
- 📖 [urllib.parse.parse_qs](https://docs.python.org/3/library/urllib.parse.html#urllib.parse.parse_qs)

---

### يوم 3 (الأربعاء 14/10): اختبار الـ Proxy + مراجعة كود ب و د

**المطلوب:**
- كتابة `tests/test_proxy.py` — اختبارات إن الترافيك بيعدي سليم
- مراجعة كود **ب** (normalizer) و **د** (config)
- التأكد إن Juice Shop شغال من ورا الـ Proxy

**لازم تكون عارف:**
1. إزاي pytest بيشتغل (fixtures, test functions, assertions)
2. إزاي `pytest-asyncio` بيختبر async functions
3. إزاي تعمل mock لـ httpx client في الاختبارات

**يذاكر منين:**
- 📺 [pytest Tutorial - 15 min](https://www.youtube.com/results?search_query=pytest+tutorial+15+minutes)
- 📖 [FastAPI Testing](https://fastapi.tiangolo.com/tutorial/testing/)
- 📖 [pytest-asyncio docs](https://pytest-asyncio.readthedocs.io/)

---

### يوم 4 (الخميس 15/10): دمج `context.py` + `normalizer.py` + مساعدة

**المطلوب:**
- دمج شغل **ب** (normalizer) مع `context.py`
- التأكد إن `normalize_context()` بتشتغل صح على `RequestContext`
- مساعدة أي عضو متأخر

---

### يوم 5 (الأحد 18/10): مراجعة شاملة + تسجيل Baseline مع هـ

**المطلوب:**
- مراجعة كل كود الأسبوع
- مساعدة **هـ** في تسجيل Baseline traffic
- التأكد إن كل حاجة شغالة بـ `docker-compose up`

---

### يوم 6 (الاثنين 19/10): البوابة أ ✅ + تخطيط الأسبوع التاني

**المطلوب:**
- تنفيذ قائمة تحقق البوابة أ (9 شروط)
- التأكد إن port 3000 مقفول من بره
- تخطيط مهام الأسبوع التاني مع التيم

---
---

## 👤 عضو ب — Security Dev

### يوم 1 (الاثنين 12/10): `waf/models.py` + بداية `waf/normalizer.py`

**المطلوب:**
- كتابة `waf/models.py` كامل (copy من الـ Architecture + أي تعديلات متفق عليها)
- بداية `waf/normalizer.py` — الهيكل و `normalize_text()` (الخطوات 1-3: URL decode + HTML entities + NFKC)

**لازم تكون عارف:**
1. إيه Python `dataclasses` وإزاي `@dataclass` بتشتغل
2. إيه Python `Enum` وليه بنستخدمه
3. إزاي URL encoding بيشتغل (`%27` = `'`, `%3C` = `<`)
4. إيه double/triple URL encoding وليه المهاجم بيعمله
5. إزاي `urllib.parse.unquote()` بتفك URL encoding
6. إيه HTML entities (`&lt;` = `<`, `&#39;` = `'`)
7. إيه Unicode NFKC normalization

**يذاكر منين:**
- 📖 [Python dataclasses](https://docs.python.org/3/library/dataclasses.html) — أول نص
- 📖 [URL Encoding Reference](https://www.w3schools.com/tags/ref_urlencode.asp)
- 📖 [urllib.parse.unquote](https://docs.python.org/3/library/urllib.parse.html#urllib.parse.unquote)
- 📖 [html.unescape](https://docs.python.org/3/library/html.html#html.unescape)
- 📖 [unicodedata.normalize](https://docs.python.org/3/library/unicodedata.html#unicodedata.normalize) — NFKC
- 📺 [WAF Evasion Techniques](https://www.youtube.com/results?search_query=WAF+evasion+techniques+encoding) — أي فيديو 10 دقايق عن التشويه

---

### يوم 2 (الثلاثاء 13/10): إكمال `normalizer.py` — الخطوات 4-7

**المطلوب:**
- إزالة Null bytes والمسافات الغريبة
- تحويل SQL comments `/**/` لمسافة
- استخراج محتوى MySQL conditional comments `/*!50000SELECT*/`
- Lowercase
- بناء `normalize_context()` اللي يطبّع كل حقول `RequestContext`

**لازم تكون عارف:**
1. إيه SQL comments وليه المهاجم بيستخدمها بدل المسافات
2. إيه MySQL conditional comments (`/*!50000...*/`) وليه MySQL بينفذها
3. إزاي regex بيشتغل في Python (`re.sub`, `re.compile`)
4. إيه Null byte injection (`\x00`)

**يذاكر منين:**
- 📖 [Python re module](https://docs.python.org/3/library/re.html) — `re.sub` و `re.compile`
- 📖 [SQL Injection via comments - OWASP](https://owasp.org/www-community/attacks/SQL_Injection)
- 📖 [MySQL conditional comments](https://dev.mysql.com/doc/refman/8.0/en/comments.html)
- 📺 [Regex in Python - 20 min](https://www.youtube.com/results?search_query=python+regex+tutorial+20+minutes)

---

### يوم 3 (الأربعاء 14/10): `tests/test_normalizer.py`

**المطلوب:**
- كتابة اختبارات لكل خطوة تطبيع:
  - URL decode عادي ومزدوج وثلاثي
  - HTML entities
  - NFKC
  - Null bytes
  - SQL comments
  - Conditional comments
  - عدّاد `decode_iterations`
- اختبار `normalize_context()` كامل

**لازم تكون عارف:**
1. إزاي تكتب pytest test functions
2. إزاي `assert` بتشتغل
3. إزاي تختبر edge cases (نص فاضي، حروف unicode غريبة)

**يذاكر منين:**
- 📖 [pytest Getting Started](https://docs.pytest.org/en/stable/getting-started.html)

---

### يوم 4 (الخميس 15/10): تثبيت `normalizer.py` + مساعدة د في Config

**المطلوب:**
- إصلاح أي bugs من المراجعة مع **أ**
- مساعدة **د** في ربط الإعدادات بالـ Normalizer (enable/disable)
- تثبيت الملف — **بعد اليوم ده مفيش تغيير في normalizer.py إلا بموافقة الكل**

---

### يوم 5 (الأحد 18/10): بداية البحث عن Signature rules

**المطلوب:**
- تحميل [OWASP CRS rules](https://github.com/coreruleset/coreruleset/tree/main/rules) والدراسة
- اختيار أهم 20-30 regex pattern من CRS
- تحويلها لصيغة `rules.json` بتاعتنا
- كتابة أول draft لقواعد SQLi

**لازم تكون عارف:**
1. إيه OWASP CRS وإزاي القواعد مكتوبة
2. إيه Paranoia Level في CRS
3. أشهر SQLi payloads (`' OR 1=1`, `UNION SELECT`, `; DROP TABLE`)
4. أشهر XSS payloads (`<script>`, `onerror=`, `javascript:`)

**يذاكر منين:**
- 📖 [OWASP CRS GitHub](https://github.com/coreruleset/coreruleset) — اقرأ README
- 📖 [CRS Rules Documentation](https://coreruleset.org/docs/rules/rules/)
- 📖 [SQL Injection Cheat Sheet - PortSwigger](https://portswigger.net/web-security/sql-injection/cheat-sheet)
- 📖 [XSS Filter Evasion - OWASP](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html)

---

### يوم 6 (الاثنين 19/10): إكمال draft القواعد + مساعدة في البوابة أ

---
---

## 👤 عضو ج — ML Engineer

### يوم 1 (الاثنين 12/10): تحميل SR-BH + إعداد بيئة التدريب

**المطلوب:**
- تحميل SR-BH dataset من Harvard Dataverse
- تحميل HttpParams من Kaggle
- إعداد `requirements-training.txt` وتجربة الـ import محلياً
- فتح Colab وتثبيت نفس الإصدارات

**لازم تكون عارف:**
1. إيه scikit-learn وإزاي تـ install و import
2. إيه TF-IDF (بشكل عام — مش محتاج رياضيات)
3. إيه Logistic Regression (بشكل عام — classifier بسيط)
4. إيه train/validation/test split وليه بنعملها
5. إيه overfitting وليه بنحجز test set
6. إزاي Google Colab بيشتغل (رفع ملفات، GPU، حفظ على Drive)

**يذاكر منين:**
- 📺 [scikit-learn Crash Course - 60 min](https://www.youtube.com/results?search_query=scikit-learn+crash+course+2024) — أي فيديو محترم
- 📺 [TF-IDF Explained Simply - 10 min](https://www.youtube.com/results?search_query=TF-IDF+explained+simply)
- 📺 [Logistic Regression Simply Explained](https://www.youtube.com/results?search_query=logistic+regression+explained+simply)
- 📖 [scikit-learn: TfidfVectorizer](https://scikit-learn.org/stable/modules/generated/sklearn.feature_extraction.text.TfidfVectorizer.html)
- 📖 [Google Colab Getting Started](https://colab.research.google.com/notebooks/intro.ipynb)
- 📖 [SR-BH Dataset - Harvard Dataverse](https://dataverse.harvard.edu/dataset.xhtml?persistentId=doi:10.7910/DVN/KLGKGQ)

---

### يوم 2 (الثلاثاء 13/10): فحص البيانات + فهم هيكل SR-BH

**المطلوب:**
- فتح SR-BH ودراسة شكل البيانات (columns, sizes, label distribution)
- عمل EDA بسيط (عدد كل فئة، أطوال الطلبات، أمثلة)
- تحديد إيه اللي فيه headers وإيه اللي فيه payloads بس
- كتابة ملاحظات عن جودة البيانات

**لازم تكون عارف:**
1. إزاي pandas بتشتغل (`pd.read_csv`, `df.head()`, `df.describe()`, `df.value_counts()`)
2. إزاي تعمل visualization بسيط (`matplotlib` أو `seaborn`)

**يذاكر منين:**
- 📺 [Pandas in 10 Minutes](https://www.youtube.com/results?search_query=pandas+10+minutes+tutorial)
- 📖 [Pandas Cheat Sheet](https://pandas.pydata.org/Pandas_Cheat_Sheet.pdf)

---

### يوم 3 (الأربعاء 14/10): بداية `training/clean_data.py`

**المطلوب:**
- كتابة هيكل `clean_data.py`
- تنفيذ hash dedup (`hashlib.sha256`)
- تنفيذ إزالة الـ headers من العينات
- ربط `normalizer.py` (من **ب**) لتطبيع النصوص

**لازم تكون عارف:**
1. إزاي `hashlib.sha256` بتشتغل
2. إزاي تستورد ملف من فولدر تاني (`from waf.normalizer import normalize_text`)

**يذاكر منين:**
- 📖 [hashlib — Python docs](https://docs.python.org/3/library/hashlib.html) — أول مثال كفاية

---

### يوم 4 (الخميس 15/10): تسجيل ترافيك Juice Shop السليم

**المطلوب:**
- مع **هـ**: كتابة `scripts/generate_baseline.py`
- سيناريوهات: تصفح، بحث، تسجيل دخول، إضافة للسلة
- حفظ في `data/baseline/`

**لازم تكون عارف:**
1. إزاي تبعت HTTP requests بـ `httpx` أو `requests`
2. إيه سيناريوهات Juice Shop الأساسية

**يذاكر منين:**
- 📖 [Juice Shop Official - Happy Path](https://pwning.owasp-juice.shop/companion-guide/latest/part1/happy-path.html)
- 📖 [httpx quickstart](https://www.python-httpx.org/quickstart/)

---

### يوم 5 (الأحد 18/10): مذاكرة ML pipeline كامل

**المطلوب:**
- مذاكرة مكثفة:
  - TF-IDF + char n-grams
  - Logistic Regression + `predict_proba`
  - `CalibratedClassifierCV`
  - `classification_report` + `confusion_matrix`
  - `train_test_split` مع stratify
- تجربة pipeline كاملة على dummy data

**يذاكر منين:**
- 📺 [Full ML Pipeline with scikit-learn - 45 min](https://www.youtube.com/results?search_query=scikit-learn+full+pipeline+tutorial)
- 📖 [TfidfVectorizer with char n-grams](https://scikit-learn.org/stable/modules/generated/sklearn.feature_extraction.text.TfidfVectorizer.html) — parameter `analyzer='char'`
- 📖 [CalibratedClassifierCV](https://scikit-learn.org/stable/modules/generated/sklearn.calibration.CalibratedClassifierCV.html)
- 📖 [Classification Report](https://scikit-learn.org/stable/modules/generated/sklearn.metrics.classification_report.html)

---

### يوم 6 (الاثنين 19/10): إكمال تنظيف SR-BH + فحص بالـ Signatures

**المطلوب:**
- أخد قواعد **ب** الأولية وتشغيلها على الفئة السليمة في SR-BH
- اللي طابق → يتنقل لـ "مشبوه"
- حفظ البيانات النظيفة في `data/cleaned/`

---
---

## 👤 عضو د — Backend Dev

### يوم 1 (الاثنين 12/10): Docker + Git + البيئة

**المطلوب:**
- إنشاء `docker-compose.yml` كامل (من الـ Architecture)
- إنشاء `Dockerfile.waf`
- إنشاء `requirements.txt` و `.env.example` و `.gitignore`
- إنشاء Git repo مع `.gitignore`
- التأكد إن `docker-compose up` بيشغّل Juice Shop
- **على Windows:** إعداد `.wslconfig` (حد الرام لـ WSL2)

**لازم تكون عارف:**
1. إيه Docker وإيه Container وإيه Image
2. إزاي `Dockerfile` بيتكتب (`FROM`, `COPY`, `RUN`, `CMD`)
3. إزاي `docker-compose.yml` بيشتغل (services, networks, volumes, ports)
4. إيه الفرق بين `internal: true` و `internal: false` في Docker networks
5. إزاي Git بيشتغل (`init`, `add`, `commit`, `branch`, `merge`)
6. إيه WSL2 وليه Docker Desktop بيحتاجه على Windows

**يذاكر منين:**
- 📺 [Docker in 30 Minutes (بالعربي)](https://www.youtube.com/results?search_query=Docker+tutorial+arabic+30+minutes)
- 📺 [Docker Compose in 12 Minutes](https://www.youtube.com/results?search_query=docker+compose+12+minutes)
- 📖 [Docker Compose File Reference](https://docs.docker.com/reference/compose-file/)
- 📖 [Docker Networking - internal](https://docs.docker.com/reference/compose-file/networks/#internal)
- 📖 [WSL2 Memory Config](https://learn.microsoft.com/en-us/windows/wsl/wsl-config#configuration-setting-for-wslconfig)
- 📺 [Git Basics in 15 Minutes](https://www.youtube.com/results?search_query=git+basics+15+minutes)

---

### يوم 2 (الثلاثاء 13/10): `waf/config_manager.py`

**المطلوب:**
- إنشاء `config.yaml` (من الـ Architecture — copy)
- كتابة `waf/config_manager.py`: `load()` و `get()` و `reload()`
- `WAFConfig` dataclass (frozen=True عشان thread-safe)

**لازم تكون عارف:**
1. إزاي YAML بيشتغل (indentation, lists, dicts)
2. إزاي `pyyaml` بتقرأ YAML في Python (`yaml.safe_load`)
3. إيه `frozen=True` في dataclass وليه بنستخدمه
4. إيه الفكرة من Hot Reload (تغيير الإعدادات بدون إعادة تشغيل)

**يذاكر منين:**
- 📖 [YAML Tutorial](https://www.yaml.info/learn/index.html) — أول 5 دقايق
- 📖 [PyYAML Documentation](https://pyyaml.org/wiki/PyYAMLDocumentation)
- 📖 [Python dataclasses - frozen](https://docs.python.org/3/library/dataclasses.html#frozen-instances)

---

### يوم 3 (الأربعاء 14/10): ربط Config بالـ Proxy + اختبارات

**المطلوب:**
- ربط `config_manager.get()` بـ `main.py` (backend_url, body_max_size)
- كتابة `tests/test_context.py`
- اختبار: config بيتحمّل صح، قيم default صح

---

### يوم 4 (الخميس 15/10): هيكل `detector.py` (بدون فحص فعلي)

**المطلوب:**
- كتابة `waf/detector.py` — الهيكل الأساسي بـ `async def detect(ctx)`
- **في الأسبوع الأول:** كل الطبقات ترجّع `ALLOW` (placeholder)
- الهيكل: whitelist → blacklist → rate_limit → static → normalize → signatures → AI
- حساب `processing_time_ms`

**لازم تكون عارف:**
1. إزاي `time.perf_counter()` بتشتغل لقياس الزمن
2. إيه try/except وليه بنلف كل طبقة فيها (fail-open)

**يذاكر منين:**
- 📖 [time.perf_counter](https://docs.python.org/3/library/time.html#time.perf_counter)

---

### يوم 5 (الأحد 18/10): ربط `normalizer.py` في `detector.py` + اختبارات

**المطلوب:**
- ربط `normalizer.normalize_context()` في `detector.py`
- ربط `config.enable_normalizer` عشان يتقفل من الإعدادات
- كتابة اختبار: الطلب بيتطبّع لما الـ normalizer enabled

---

### يوم 6 (الاثنين 19/10): تثبيت البيئة + البوابة أ + مذاكرة SQLite

**المطلوب:**
- المشاركة في البوابة أ
- بداية مذاكرة SQLite و WAL mode (تحضير للأسبوع التالت)

**يذاكر منين (تحضير للأسبوع 3):**
- 📺 [SQLite Tutorial Python - 20 min](https://www.youtube.com/results?search_query=sqlite+python+tutorial)
- 📖 [SQLite WAL Mode](https://www.sqlite.org/wal.html)
- 📖 [Python sqlite3 module](https://docs.python.org/3/library/sqlite3.html)

---
---

## 👤 عضو هـ — QA + Frontend

### يوم 1 (الاثنين 12/10): إعداد بيئة الاختبار + `tests/conftest.py`

**المطلوب:**
- تثبيت pytest و pytest-asyncio
- إنشاء `tests/conftest.py` بـ fixtures مشتركة (fake request, test client)
- إنشاء `tests/payloads/benign.txt` — طلبات سليمة للاختبار
- التأكد إن `pytest` بيشتغل

**لازم تكون عارف:**
1. إزاي pytest بيشتغل (اكتشاف الاختبارات، fixtures، markers)
2. إيه conftest.py وليه بنحط fixtures فيه
3. إيه `httpx.AsyncClient` كـ test client لـ FastAPI

**يذاكر منين:**
- 📺 [pytest Tutorial - Full](https://www.youtube.com/results?search_query=pytest+full+tutorial+2024)
- 📖 [pytest fixtures](https://docs.pytest.org/en/stable/how-to/fixtures.html)
- 📖 [FastAPI TestClient](https://fastapi.tiangolo.com/tutorial/testing/)

---

### يوم 2 (الثلاثاء 13/10): `tests/test_proxy.py`

**المطلوب:**
- اختبار: GET request يوصل ويرجع 200
- اختبار: POST مع body يوصل سليم
- اختبار: body أكبر من 1MB يتقطع
- اختبار: backend وقع → 502

---

### يوم 3 (الأربعاء 14/10): اختبارات يدوية + مساعدة ب في الـ Normalizer tests

**المطلوب:**
- اختبار يدوي: فتح Juice Shop من `localhost:8080` ولعب سيناريوهات
- تسجيل أي مشاكل
- مساعدة **ب** في كتابة `test_normalizer.py`

---

### يوم 4 (الخميس 15/10): تسجيل Baseline traffic مع ج

**المطلوب:**
- مع **ج**: تشغيل `generate_baseline.py`
- لعب سيناريوهات Juice Shop يدوياً والـ Proxy يسجل
- سيناريوهات: تصفح رئيسية، بحث عن "apple juice"، تسجيل حساب، تسجيل دخول، إضافة للسلة، checkout
- حفظ في `data/baseline/`

**لازم تكون عارف:**
1. إزاي Juice Shop بيشتغل (واجهة المستخدم)
2. إيه السيناريوهات السليمة اللي المستخدم العادي يعملها

**يذاكر منين:**
- 📖 [Juice Shop - Happy Path](https://pwning.owasp-juice.shop/companion-guide/latest/part1/happy-path.html)
- 📺 [OWASP Juice Shop Walkthrough](https://www.youtube.com/results?search_query=OWASP+juice+shop+walkthrough)

---

### يوم 5 (الأحد 18/10): مذاكرة Streamlit (تحضير للأسبوع 3)

**المطلوب:**
- مذاكرة Streamlit + بناء صفحة تجريبية بسيطة
- مذاكرة Plotly charts
- تصميم wireframe للـ Dashboard على ورقة

**يذاكر منين:**
- 📺 [Streamlit Tutorial - 30 min](https://www.youtube.com/results?search_query=streamlit+tutorial+30+minutes+2024)
- 📖 [Streamlit Official - Get Started](https://docs.streamlit.io/get-started)
- 📖 [Streamlit st.metric](https://docs.streamlit.io/develop/api-reference/data/st.metric)
- 📖 [Streamlit st.fragment](https://docs.streamlit.io/develop/api-reference/execution-flow/st.fragment) — التحديث الدوري
- 📖 [Plotly Express - Scatter, Line, Pie](https://plotly.com/python/plotly-express/)

---

### يوم 6 (الاثنين 19/10): البوابة أ + بداية تحضير payloads الهجوم

**المطلوب:**
- المشاركة في البوابة أ
- إنشاء `tests/payloads/sqli.txt` و `xss.txt` — عينات payloads للاختبار
- تحميل عينات من [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

---
---

# الأسبوع التاني: Detection Engine (20–26 أكتوبر)

---

## 👤 عضو أ — Tech Lead

| اليوم | التاريخ | المهمة |
|---|---|---|
| 7 | الثلاثاء 20/10 | مراجعة `rules.json` مع **ب** + ربطها في `detector.py` |
| 8 | الأربعاء 21/10 | كتابة `waf/ai_engine.py` — `load_models()` + `predict()` + `warmup()` + `verify_checksum()` |
| 9 | الخميس 22/10 | ربط `ai_engine.py` في `detector.py` + Short-Circuit + LRU Cache |
| 10 | الأحد 25/10 | مراجعة موديلات **ج** + دمج الكل + Integration testing |
| 11 | الاثنين 26/10 | أول قياس Latency (مؤقتات داخلية) + **البوابة ب** + تثبيت KPIs |

**لازم يكون عارف (إضافي):**
1. إزاي `joblib.load()` بتحمّل pickle files
2. إيه `functools.lru_cache` وإزاي نعملها بـ hash
3. إزاي `hashlib.sha256` بتتحقق من سلامة الملفات

**يذاكر منين:**
- 📖 [joblib.load](https://joblib.readthedocs.io/en/latest/generated/joblib.load.html)
- 📖 [functools.lru_cache](https://docs.python.org/3/library/functools.html#functools.lru_cache)

---

## 👤 عضو ب — Security Dev

| اليوم | التاريخ | المهمة |
|---|---|---|
| 7 | الثلاثاء 20/10 | إكمال `rules.json` — SQLi (10 rules) + XSS (8 rules) |
| 8 | الأربعاء 21/10 | إضافة Path Traversal (5 rules) + Command Injection (5 rules) + كتابة `signatures.py`: `load_rules()` + `scan()` + `validate_rule()` |
| 9 | الخميس 22/10 | `tests/test_signatures.py` — اختبار كل rule بـ payloads حقيقية + اختبار ReDoS + قياس FP على baseline |
| 10 | الأحد 25/10 | إصلاح rules اللي عملت FP + ضبط paranoia levels |
| 11 | الاثنين 26/10 | مساعدة **أ** في الدمج + مراجعة |

**لازم يكون عارف (إضافي):**
1. إيه ReDoS وإزاي تتجنبه (لا nested quantifiers)
2. إزاي `re.compile` مع `re.IGNORECASE` بتشتغل
3. إيه path traversal payloads (`../`, `..%2f`, `....//`)
4. إيه command injection payloads (`; ls`, `| cat /etc/passwd`, `` `whoami` ``)

**يذاكر منين:**
- 📖 [ReDoS - OWASP](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)
- 📖 [Path Traversal - PortSwigger](https://portswigger.net/web-security/file-path-traversal)
- 📖 [Command Injection - PortSwigger](https://portswigger.net/web-security/os-command-injection)

---

## 👤 عضو ج — ML Engineer

| اليوم | التاريخ | المهمة |
|---|---|---|
| 7 | الثلاثاء 20/10 | إكمال `training/clean_data.py` — dedup بالـ hash + فحص بالـ signatures + تنظيف + حفظ |
| 8 | الأربعاء 21/10 | توليد هجمات مشوهة بـ sqlmap (`--tamper=space2comment,charencode,randomcase`) + إضافتها للبيانات + التقسيم (`prepare_features.py`) |
| 9 | الخميس 22/10 | `training/train_lr.py` — TF-IDF + Logistic Regression + Calibration + حفظ pkl + checksums |
| 10 | الأحد 25/10 | `training/evaluate.py` — classification_report + confusion matrix + Macro F1 + كتابة تقرير التقييم |
| 11 | الاثنين 26/10 | `waf/feature_extractor.py` + تسليم الملفات لـ **أ** للدمج |

**لازم يكون عارف (إضافي):**
1. إزاي sqlmap بيشتغل مع `--tamper` scripts
2. إيه `stratify` في `train_test_split` وليه مهم
3. إزاي `joblib.dump` بتحفظ الموديل
4. إيه `class_weight='balanced'` في LogisticRegression
5. إزاي تقرأ Confusion Matrix

**يذاكر منين:**
- 📺 [sqlmap Tutorial](https://www.youtube.com/results?search_query=sqlmap+tutorial+tamper+scripts)
- 📖 [sklearn train_test_split](https://scikit-learn.org/stable/modules/generated/sklearn.model_selection.train_test_split.html)
- 📖 [sklearn Confusion Matrix](https://scikit-learn.org/stable/modules/generated/sklearn.metrics.confusion_matrix.html)
- 📖 [joblib dump/load](https://joblib.readthedocs.io/en/latest/generated/joblib.dump.html)
- 📖 [LogisticRegression - class_weight](https://scikit-learn.org/stable/modules/generated/sklearn.linear_model.LogisticRegression.html)

---

## 👤 عضو د — Backend Dev

| اليوم | التاريخ | المهمة |
|---|---|---|
| 7 | الثلاثاء 20/10 | مذاكرة SQLite + كتابة `waf/db.py` — `init_db()` مع الـ SQL schema كامل |
| 8 | الأربعاء 21/10 | إكمال `db.py` — `insert_batch()` + `insert_alert()` + `update_alert_status()` |
| 9 | الخميس 22/10 | كتابة `waf/event_queue.py` — Queue + `put()` + `background_writer()` (الهيكل بس، بدون geoip/alerts) |
| 10 | الأحد 25/10 | اختبار: أحداث بتتكتب في SQLite صح + WAL mode شغال |
| 11 | الاثنين 26/10 | مساعدة **أ** في الدمج + مراجعة |

**لازم يكون عارف (إضافي):**
1. إزاي `asyncio.Queue` بتشتغل
2. إيه WAL mode في SQLite وليه بنحتاجه
3. إزاي تعمل batch insert في SQLite (`executemany`)
4. إيه `asyncio.create_task` وإزاي تشغّل background task

**يذاكر منين:**
- 📖 [asyncio.Queue](https://docs.python.org/3/library/asyncio-queue.html)
- 📖 [SQLite WAL](https://www.sqlite.org/wal.html)
- 📖 [sqlite3 executemany](https://docs.python.org/3/library/sqlite3.html#sqlite3.Cursor.executemany)
- 📖 [asyncio.create_task](https://docs.python.org/3/library/asyncio-task.html#asyncio.create_task)

---

## 👤 عضو هـ — QA + Frontend

| اليوم | التاريخ | المهمة |
|---|---|---|
| 7 | الثلاثاء 20/10 | تجهيز payloads اختبار كاملة: `sqli.txt`, `xss.txt`, `traversal.txt`, `cmdi.txt` |
| 8 | الأربعاء 21/10 | `tests/test_signatures.py` مع **ب** — كل payload لازم يتمسك |
| 9 | الخميس 22/10 | اختبار FP: تشغيل baseline traffic عبر الـ WAF والتأكد مفيش حجب خاطئ |
| 10 | الأحد 25/10 | `tests/test_detector.py` — اختبار التكامل: request → detect → result |
| 11 | الاثنين 26/10 | أول قياس Latency مع **أ** — تسجيل p50/p95 لكل مسار |

**لازم يكون عارف (إضافي):**
1. إزاي تقيس زمن تنفيذ في Python (`time.perf_counter`)
2. إيه p50 و p95 (median و 95th percentile)
3. إزاي `numpy.percentile` بتحسبها

**يذاكر منين:**
- 📖 [numpy.percentile](https://numpy.org/doc/stable/reference/generated/numpy.percentile.html)

---
---

# الأسبوع التالت: Backend + Dashboard (27 أكتوبر – 2 نوفمبر)

---

## 👤 عضو أ — Tech Lead

| اليوم | التاريخ | المهمة |
|---|---|---|
| 12 | الثلاثاء 27/10 | مراجعة + ربط Rate Limiter في `detector.py` |
| 13 | الأربعاء 28/10 | ربط AbuseIPDB + Blacklist + GeoIP في `background_writer` |
| 14 | الخميس 29/10 | ربط Alert Engine في `background_writer` |
| 15 | الأحد 1/11 | Integration testing: هجوم → حجب → event → SQLite → Dashboard |
| 16 | الاثنين 2/11 | **البوابة ج** + إصلاح أي مشاكل |

---

## 👤 عضو ب — Security Dev

| اليوم | التاريخ | المهمة |
|---|---|---|
| 12 | الثلاثاء 27/10 | `waf/rate_limiter.py` — Token Bucket + `check()` + `cleanup()` |
| 13 | الأربعاء 28/10 | `tests/test_rate_limiter.py` + ربط login paths من config |
| 14 | الخميس 29/10 | `waf/blacklist.py` — strikes + ban + escalation + whitelist |
| 15 | الأحد 1/11 | مساعدة **هـ** في Dashboard (عرض الـ payloads كنص آمن) |
| 16 | الاثنين 2/11 | مراجعة أمنية شاملة (XSS في Dashboard, pickle, etc.) |

**لازم يكون عارف (إضافي):**
1. إيه Token Bucket algorithm
2. إزاي الـ whitelist بتشتغل مع الـ blacklist

**يذاكر منين:**
- 📖 [Token Bucket Algorithm Explained](https://en.wikipedia.org/wiki/Token_bucket) — أول 3 فقرات
- 📺 [Rate Limiting Explained - 10 min](https://www.youtube.com/results?search_query=token+bucket+rate+limiting+explained)

---

## 👤 عضو ج — ML Engineer

| اليوم | التاريخ | المهمة |
|---|---|---|
| 12 | الثلاثاء 27/10 | `waf/threat_intel.py` — AbuseIPDB client + cache في SQLite |
| 13 | الأربعاء 28/10 | `waf/geoip.py` — DB-IP Lite + `enrich()` |
| 14 | الخميس 29/10 | اختبار: AbuseIPDB + GeoIP شغالين صح |
| 15 | الأحد 1/11 | (مشروط) `training/train_lgbm.py` لو فيه وقت |
| 16 | الاثنين 2/11 | مساعدة في البوابة ج |

**لازم يكون عارف (إضافي):**
1. إزاي AbuseIPDB API بيشتغل (GET request مع API key)
2. إزاي `geoip2` library بتقرأ قاعدة البيانات المحلية
3. إيه العناوين الخاصة (127.0.0.1, 10.x, 172.16-31.x, 192.168.x) اللي مش بنبعتها لـ AbuseIPDB

**يذاكر منين:**
- 📖 [AbuseIPDB API Docs](https://docs.abuseipdb.com/#check-endpoint)
- 📖 [geoip2 Python Library](https://geoip2.readthedocs.io/en/latest/)
- 📖 [DB-IP Lite Download](https://db-ip.com/db/download/ip-to-city-lite)
- 📖 [Private IP Ranges](https://en.wikipedia.org/wiki/Private_network)

---

## 👤 عضو د — Backend Dev

| اليوم | التاريخ | المهمة |
|---|---|---|
| 12 | الثلاثاء 27/10 | ربط `event_queue.py` بـ `db.py` + اختبار الكتابة على دفعات |
| 13 | الأربعاء 28/10 | `waf/alerts.py` — `process()` + dedup + severity rules |
| 14 | الخميس 29/10 | اختبار: alert بيتولد صح + dedup شغال |
| 15 | الأحد 1/11 | `dashboard/db_reader.py` — كل الـ query functions |
| 16 | الاثنين 2/11 | مساعدة **هـ** في ربط الـ Dashboard بـ `db_reader.py` |

**لازم يكون عارف (إضافي):**
1. إزاي SQLite read-only connection بتشتغل
2. إيه SQL GROUP BY و COUNT و ORDER BY

**يذاكر منين:**
- 📖 [SQLite Read-Only](https://www.sqlite.org/uri.html) — `?mode=ro`
- 📖 [SQL GROUP BY](https://www.w3schools.com/sql/sql_groupby.asp)

---

## 👤 عضو هـ — QA + Frontend

| اليوم | التاريخ | المهمة |
|---|---|---|
| 12 | الثلاثاء 27/10 | `dashboard/app.py` — الصفحة الرئيسية: 4 عدادات + جدول أحداث |
| 13 | الأربعاء 28/10 | إضافة رسم زمني (Plotly line chart) + أنواع الهجمات (bar/pie) |
| 14 | الخميس 29/10 | `dashboard/pages/2_alerts.py` — قائمة + severity colors + زر acknowledge |
| 15 | الأحد 1/11 | إضافة فلاتر + `st.fragment(run_every=2s)` للتحديث + `st.toast` |
| 16 | الاثنين 2/11 | `Dockerfile.dashboard` + اختبار كامل مع `docker-compose --profile full up` |

**لازم يكون عارف (إضافي):**
1. إزاي Streamlit multi-page app بتشتغل (مجلد `pages/`)
2. إزاي `st.columns` و `st.metric` و `st.dataframe`
3. إزاي Plotly Express بتعمل charts
4. إزاي `st.fragment` بتعمل تحديث دوري

**يذاكر منين:**
- 📖 [Streamlit Multi-page Apps](https://docs.streamlit.io/develop/concepts/multipage-apps)
- 📖 [st.fragment](https://docs.streamlit.io/develop/api-reference/execution-flow/st.fragment)
- 📖 [st.toast](https://docs.streamlit.io/develop/api-reference/status/st.toast)
- 📖 [Plotly Express in Streamlit](https://docs.streamlit.io/develop/api-reference/charts/st.plotly_chart)

---
---

# الأسبوع الرابع: Testing & Delivery (3–10 نوفمبر)

---

## 👤 عضو أ — Tech Lead

| اليوم | التاريخ | المهمة |
|---|---|---|
| 17 | الثلاثاء 3/11 | 🛡️ **هامش** — إصلاح bugs + `docker-compose up` بأمر واحد + Demo mode |
| 18 | الأربعاء 4/11 | 🛡️ **هامش** — LightGBM integration (مشروط) أو تحسينات |
| 19 | الخميس 5/11 | `scripts/demo.py` — سكريبت العرض الحي |
| 20 | الأحد 8/11 | مراجعة التقرير + الشرائح + بروفة أولى |
| 21 | الاثنين 9/11 | بروفة ثانية + تجميد الكود |
| 22 | الثلاثاء 10/11 | **التسليم** |

---

## 👤 عضو ب — Security Dev

| اليوم | التاريخ | المهمة |
|---|---|---|
| 17 | الثلاثاء 3/11 | إعداد ModSecurity + CRS في Docker container للمقارنة |
| 18 | الأربعاء 4/11 | تشغيل نفس الـ payloads على ModSecurity وتسجيل النتائج |
| 19 | الخميس 5/11 | جدول مقارنة: WAF بتاعنا vs ModSecurity (Detection Rate, FPR) |
| 20 | الأحد 8/11 | كتابة قسم Red Team في التقرير |
| 21 | الاثنين 9/11 | مراجعة + بروفة |
| 22 | الثلاثاء 10/11 | **التسليم** |

**لازم يكون عارف:**
1. إزاي ModSecurity + CRS بيتركبوا في Docker
2. إزاي تقارن نتيجتين (hit rates)

**يذاكر منين:**
- 📖 [ModSecurity Docker](https://hub.docker.com/r/owasp/modsecurity-crs) — `docker pull owasp/modsecurity-crs`
- 📖 [CRS Documentation](https://coreruleset.org/docs/)

---

## 👤 عضو ج — ML Engineer

| اليوم | التاريخ | المهمة |
|---|---|---|
| 17 | الثلاثاء 3/11 | تشغيل `evaluate.py` على test set النهائي + أرقام KPIs |
| 18 | الأربعاء 4/11 | مقارنة S0/S2/S4 — أرقام Detection + Latency |
| 19 | الخميس 5/11 | كتابة تقرير تقييم الموديلات (Macro F1, Confusion Matrix, Calibration curve) |
| 20 | الأحد 8/11 | كتابة الأقسام التقنية في التقرير (AI pipeline, training, results) |
| 21 | الاثنين 9/11 | مراجعة + بروفة |
| 22 | الثلاثاء 10/11 | **التسليم** |

---

## 👤 عضو د — Backend Dev

| اليوم | التاريخ | المهمة |
|---|---|---|
| 17 | الثلاثاء 3/11 | sqlmap ضد الـ WAF مع tamper scripts + تسجيل النتائج |
| 18 | الأربعاء 4/11 | ZAP automated scan ضد الـ WAF + تسجيل |
| 19 | الخميس 5/11 | Locust benchmark على جهاز تاني: p50/p95/p99 |
| 20 | الأحد 8/11 | كتابة التقرير التقني (Architecture, components, decisions) |
| 21 | الاثنين 9/11 | `README.md` + مراجعة |
| 22 | الثلاثاء 10/11 | **التسليم** |

**لازم يكون عارف:**
1. إزاي sqlmap بيشتغل (`sqlmap -u URL --tamper=...`)
2. إزاي ZAP automated scan بيشتغل
3. إزاي Locust بيعمل load testing

**يذاكر منين:**
- 📺 [sqlmap Tutorial](https://www.youtube.com/results?search_query=sqlmap+tutorial+beginners)
- 📖 [OWASP ZAP Getting Started](https://www.zaproxy.org/getting-started/)
- 📖 [Locust Quickstart](https://docs.locust.io/en/stable/quickstart.html)
- 📺 [Locust Load Testing - 15 min](https://www.youtube.com/results?search_query=locust+load+testing+python)

---

## 👤 عضو هـ — QA + Frontend

| اليوم | التاريخ | المهمة |
|---|---|---|
| 17 | الثلاثاء 3/11 | اختبار FP نهائي: كل baseline traffic يعدي بدون حجب |
| 18 | الأربعاء 4/11 | تحسينات Dashboard (ألوان، ترتيب، UX) |
| 19 | الخميس 5/11 | شرائح العرض (PowerPoint / Google Slides) |
| 20 | الأحد 8/11 | الملخص التنفيذي (صفحة واحدة) |
| 21 | الاثنين 9/11 | بروفة + screenshots للـ Dashboard |
| 22 | الثلاثاء 10/11 | **التسليم** |

---
---

## ملخص مرئي

```
         أسبوع 1          أسبوع 2          أسبوع 3          أسبوع 4
       Foundation        Detection      Backend+Dashboard    Testing
       ──────────        ─────────      ─────────────────    ───────
أ  │ main+proxy+ctx  │ ai_engine+det  │ ربط+integration  │ demo+بروفة    │
ب  │ models+normaliz │ sigs+rules.json│ rate_limit+BL     │ ModSec مقارنة  │
ج  │ SR-BH+clean     │ train+evaluate │ AbuseIPDB+geoip   │ أرقام+تقرير   │
د  │ Docker+config   │ db+event_queue │ alerts+db_reader   │ sqlmap+locust  │
هـ │ tests+baseline  │ test payloads  │ Dashboard UI       │ slides+FP test │
```

> [!TIP]
> **اطبعوا الجدول ده وعلّقوه.** كل واحد يشوف عموده كل صبح ويعرف بالظبط المطلوب منه.
