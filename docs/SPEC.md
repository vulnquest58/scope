# `scope` — مواصفة تنفيذية

> **الهدف من هذا الملف:** وكيل يستطيع بناء المشروع كاملًا منه، بلا سؤال واحد
> وبلا تخمين. كل توقيع دالة، كل حقل بيانات، كل حالة خطأ، وكل معيار قبول مذكور
> صراحةً هنا.

**الإصدار:** 2.0 · **التاريخ:** 2026-11-01 · **الترخيص:** MIT
**الحالة:** جاهز للتنفيذ · **اللغة:** Go 1.22+

---

## ٠. كيف تُقرأ هذه المواصفة

| القسم | يُلزم المنفّذ بـ |
|---|---|
| §1–§3 | البنية والملفات — أسماء الوحدات ثابتة |
| §4–§6 | نموذج البيانات والمحرّك — التواقيع والترتيب ثابتة |
| §7–§8 | طبقات الإنفاذ والسجل — العقود ثابتة |
| §9–§12 | الواجهة والأخطاء والاختبار — السلوك ثابت |
| §13 | معايير القبول — البوابة النهائية |

**قاعدة حاكمة:** كل ما هو **ثابت** مذكور بصيغة `يجب`. ما هو **اقتراح** مذكور
بصيغة `يمكن`. عند الشك، الثابت يفوز.

---

## ١. النطاق وغير النطاق

### ١.١ ما يفعله المشروع

طبقة إنفاذ تُوضع بين أي أداة أمنية والشبكة، تقرّر لكل حزمة صادرة: مسموحة أم
مرفوضة، وفق سياسة نطاق مُصرَّح به، وتُنتج سجلًا موقَّعًا بكل قرار.

### ١.٢ ما لا يفعله — ممنوع التنفيذ

| ممنوع | السبب |
|---|---|
| اكتشاف نطاقات تلقائيًا | الأداة تُنفّذ سياسة، لا تُنتجها |
| فحص الهدف بنفسه | ليست ماسحًا |
| تعديل الأوامر المارّة | الأداة تعمل كما هي؛ هذا عقد الثقة |
| تجاوز عند الشك | فشل مغلق دائمًا |
| صلاحيات إدارية إلزامية | M2 يجب أن يعمل بلا root |
| تخزين اعتمادات المنصّة | المستخدم يصدّر YAML أو يمرّر متغيّر بيئة |

---

## ٢. بنية الملفات — إلزامية

```
scope/
├── cmd/scope/main.go            نقطة الدخول؛ لا منطق
├── internal/
│   ├── policy/
│   │   ├── policy.go            النموذج + التحميل
│   │   ├── validate.go          التحقق من الصحة
│   │   ├── match.go             مطابقة wildcard/CIDR
│   │   └── provider.go          قائمة مزوّدي الاستضافة الخارجية
│   ├── decide/
│   │   ├── decide.go            المحرّك — دالة واحدة عامة
│   │   ├── reasons.go           رموز الرفض
│   │   └── rate.go              محدّد المعدّل
│   ├── enforce/
│   │   ├── proxy.go             L7 — بروكسي HTTP/HTTPS
│   │   ├── dns.go               L3 — مُحلّل محلي
│   │   ├── connect.go           L4 — شيم connect (per-OS)
│   │   └── runner.go            تشغيل الأمر مع الحقن
│   ├── log/
│   │   ├── journal.go           سجل JSONL إضافي
│   │   └── sign.go              توقيع Ed25519
│   └── cli/
│       ├── root.go              تحليل الأوامر
│       ├── run.go               أمر run
│       ├── check.go             أمر check
│       └── report.go            صياغة المخرجات
├── testdata/
│   ├── policy_valid.yaml
│   ├── policy_expired.yaml
│   ├── policy_bad_syntax.yaml
│   └── expect/                  ملفات الذهب (golden files)
├── docs/SPEC.md                 هذا الملف
├── go.mod
└── README.md
```

**قاعدة:** لا ملف `.go` خارج هذه الشجرة. لا حزمة `utils`.

---

## ٣. الاعتماديات — مسموح فقط

| الحزمة | الإصدار | لماذا | البديل |
|---|---|---|---|
| `golang.org/x/crypto/ed25519` | latest | توقيع السجل | stdlib `crypto/ed25519` (مفضّل) |
| `gopkg.in/yaml.v3` | v3.0.1 | تحليل السياسة | — إلزامي |
| `golang.org/x/time/rate` | latest | محدّد المعدّل | تنفيذ يدوي (45 سطرًا) |

**ممنوع:** أي مكتبة بروكسي جاهزة، أي مكتبة DNS خارجية، أي ORM.
**السبب:** كل واحدة تضيف سطح فشل في المسار الحرج، والمسار الحرج هو الأمان.

`go.mod` يبدأ بـ:
```
module github.com/vulnquest58/scope
go 1.22
```

---

## ٤. نموذج البيانات — إلزامي حرفيًا

### ٤.١ `policy.Policy`

```go
type Policy struct {
    Program     string     `yaml:"program"`       // إلزامي، غير فارغ
    Fetched     time.Time  `yaml:"fetched"`       // إلزامي
    Expires     time.Time  `yaml:"expires"`       // إلزامي، > Fetched
    Levels      Levels     `yaml:"levels"`
    Windows     []Window   `yaml:"windows"`       // فارغة = مسموح دائمًا
    Rate        Rate       `yaml:"rate"`
    Allow       []string   `yaml:"allow"`         // إلزامي، عنصر واحد على الأقل
    Deny        []DenyRule `yaml:"deny"`
}

type Levels struct {
    Max int `yaml:"max"`   // 0..3، الافتراضي 1
}

type Window struct {
    Days     []string `yaml:"days"`      // mon..sun، أو ["*"]
    Hours    []string `yaml:"hours"`     // "09:00-18:00"، أو ["*"]
    Timezone string   `yaml:"timezone"`  // IANA، الافتراضي UTC
}

type Rate struct {
    PerHostRPS float64 `yaml:"per_host_rps"` // الافتراضي 5
    GlobalRPS  float64 `yaml:"global_rps"`   // الافتراضي 20
    Burst      int     `yaml:"burst"`        // الافتراضي 10
}

type DenyRule struct {
    Reason string   `yaml:"reason"` // إلزامي
    Match  []string `yaml:"match"`  // إلزامي، wildcard أو CIDR
}
```

**حقول محسوبة عند التحميل (غير موجودة في YAML):**

```go
type compiledPolicy struct {
    Policy
    allowExact   map[string]struct{}      // مطابقات حرفية
    allowWild    []wildcard               // مطابقات *.x
    allowNets    []netip.Prefix           // CIDR
    denyWild     []wildcard
    denyNets     []netip.Prefix
    denyExact    map[string]string        // host -> reason
    location     *time.Location
}
```

### ٤.٢ `decide.Decision`

```go
type Verdict int

const (
    Allow Verdict = iota
    Deny
)

type Decision struct {
    Verdict  Verdict
    Reason   Reason      // نوع معدود، لا نص حرّ
    Rule     string      // مرجع السياسة، مثل "deny[2].match[0]" أو "allow[1]"
    Target   string      // الاسم أو العنوان كما ورد
    Resolved netip.Addr  // العنوان الفعلي إن وُجد
    Level    int
    TS       time.Time
}
```

### ٤.٣ `decide.Reason` — التعداد الكامل

```go
type Reason string

const (
    ReasonAllow           Reason = "allow"
    ReasonPolicyMissing   Reason = "policy-missing"
    ReasonPolicyExpired   Reason = "policy-expired"
    ReasonPolicyInvalid   Reason = "policy-invalid"
    ReasonOutsideWindow   Reason = "outside-window"
    ReasonRateLimited     Reason = "rate-limited"
    ReasonUnresolvable    Reason = "unresolvable"
    ReasonExplicitDeny    Reason = "explicit-deny"
    ReasonThirdPartyHost  Reason = "third-party-host"
    ReasonOutsideWildcard Reason = "outside-wildcard"
    ReasonLevelTooHigh    Reason = "level-too-high"
    ReasonEngineError     Reason = "engine-error"
)
```

**قاعدة:** كل `Reason` عدا `ReasonAllow` تعني رفضًا. لا استثناء.

---

## ٥. مخطط السياسة — التحقق الإلزامي

### ٥.١ ترتيب التحقق

يُتحقق بهذا الترتيب **حرفيًا**، وأول فشل يوقف التحميل:

| # | الشرط | الخطأ |
|---|---|---|
| 1 | YAML صالح | `policy-invalid: yaml: <detail>` |
| 2 | `program` غير فارغ | `policy-invalid: program is required` |
| 3 | `fetched` و`expires` موجودان | `policy-invalid: fetched/expires required` |
| 4 | `expires > fetched` | `policy-invalid: expires must be after fetched` |
| 5 | `levels.max` في 0..3 | `policy-invalid: levels.max out of range` |
| 6 | `allow` غير فارغ | `policy-invalid: allow must list at least one entry` |
| 7 | كل عنصر في `allow` يُحلّل | `policy-invalid: allow[2]: bad wildcard "a.*.b"` |
| 8 | كل `deny[i].reason` غير فارغ | `policy-invalid: deny[1].reason is required` |
| 9 | كل `deny[i].match` غير فارغ | `policy-invalid: deny[1].match is empty` |
| 10 | `timezone` صالح | `policy-invalid: unknown timezone "Mars/Base"` |
| 11 | `hours` بصيغة `HH:MM-HH:MM` | `policy-invalid: hours[0]: bad range "9-18"` |
| 12 | `days` من المجموعة المعروفة | `policy-invalid: days contains "funday"` |

### ٥.٢ قواعد المطابقة — إلزامية

**Wildcard:**
```
"*.example.com"  يطابق  a.example.com        ✅
"*.example.com"  يطابق  a.b.example.com      ❌ (نجمتان)
"*.example.com"  يطابق  example.com          ❌ (الأصل نفسه)
"*.example.com"  يطابق  EXAMPLE.COM          ❌ (حساس للحالة؟ لا — يُوحَّد)
"example.com"    يطابق  example.com          ✅
"example.com"    يطابق  www.example.com      ❌
```

**تُوحَّد كل الأسماء إلى أحرف صغيرة قبل المطابقة. تُزال النقطة النهائية.**

**CIDR:** `203.0.113.0/24` يطابق عناوين IPv4 فقط. `::/0` يطابق IPv6 فقط.
لا خلط بين العائلتين.

**الأولوية — إلزامية بهذا الترتيب:**

```
1. denyExact[host]      → رفض فوري
2. denyWild  أي مطابقة  → رفض
3. denyNets  أي مطابقة  → رفض
4. allowExact[host]     → مرشّح للقبول
5. allowWild أي مطابقة  → مرشّح للقبول
6. allowNets أي مطابقة  → مرشّح للقبول
7. لا شيء               → رفض outside-wildcard
```

**لماذا `deny` أولًا:** لو فحصنا `allow` أولًا، لكان `*.example.com` في `allow`
يغلب `status.example.com` في `deny` — وهذا يناقض الغرض كله.

### ٥.٣ كشف الاستضافة الخارجية — إلزامي

```go
func ThirdParty(chain []string) (provider string, ok bool)
```

**الخوارزمية:**

```
1. لكل اسم في سلسلة CNAME (بما فيها الاسم الأصلي):
2.   طبّع الاسم (أحرف صغيرة، بلا نقطة نهائية)
3.   لكل لاحقة في ProviderSuffixes:
4.     إن انتهى الاسم باللاحقة → أعد (اسم المزوّد, true)
5. أعد ("", false)
```

**`ProviderSuffixes` — القائمة الإلزامية الدنيا:**

```go
var ProviderSuffixes = map[string]string{
    ".zendesk.com":          "Zendesk",
    ".statuspage.io":        "Statuspage",
    ".herokuapp.com":        "Heroku",
    ".cloudfront.net":       "CloudFront",
    ".fastly.net":           "Fastly",
    ".akamaiedge.net":       "Akamai",
    ".azureedge.net":        "Azure CDN",
    ".googleusercontent.com": "Google",
    ".github.io":            "GitHub Pages",
    ".shopify.com":          "Shopify",
    ".myshopify.com":        "Shopify",
    ".salesforce.com":       "Salesforce",
    ".force.com":            "Salesforce",
    ".wpengine.com":         "WP Engine",
    ".netlify.app":          "Netlify",
    ".vercel.app":           "Vercel",
    ".amazonaws.com":        "AWS",
    ".cloudapp.net":         "Azure",
    ".trafficmanager.net":   "Azure TM",
}
```

**قاعدة حاسمة:** إن كان الاسم **مطابقًا حرفيًا** لعنصر في `allow`، فهو مسموح حتى
لو طابق لاحقة مزوّد. الاستثناء الصريح يتفوّق على الاستنتاج.

```
allow: ["status.example.com"]
CNAME: status.example.com → acme.statuspage.io
القرار: مسموح (استثناء صريح)
```

---

## ٦. محرّك القرار — الخوارزمية

### ٦.١ التوقيع

```go
func (e *Engine) Decide(ctx context.Context, target string, level int) Decision
```

**العقد:** لا يُرجع `error`. كل فشل يُعبَّر عنه بـ`Decision.Verdict == Deny` و
`Reason` مناسب. السبب: متصل الحزمة يجب ألّا يُسقط الحزمة بصمت.

### ٦.٢ الترتيب الإلزامي

```
 1. إن لم تُحمّل السياسة        → Deny(policy-missing)   [فشل مغلق]
 2. إن فشل التحقق              → Deny(policy-invalid)
 3. إن كان now > Expires       → Deny(policy-expired)
 4. إن كان now < Fetched       → Deny(policy-expired)    [ساعة معكوبة]
 5. إن كان خارج النافذة        → Deny(outside-window)
 6. إن تجاوز الحدّ             → Deny(rate-limited)
 7. إن كان level > Levels.Max  → Deny(level-too-high)
 8. حلّ الاسم:
    أ. فشل التحليل             → Deny(unresolvable)      [فشل مغلق]
    ب. نجح                     → تابع بالعنوان
 9. denyExact(الاسم)           → Deny(explicit-deny)
10. denyWild(الاسم)            → Deny(explicit-deny)
11. denyNets(العنوان)          → Deny(explicit-deny)
12. سلسلة CNAME:
    أ. مزوّد خارجي وليس استثناءً → Deny(third-party-host)
13. allowExact(الاسم)          → Allow
14. allowWild(الاسم)           → Allow
15. allowNets(العنوان)         → Allow
16. لا شيء                     → Deny(outside-wildcard)
```

**لماذا الخطوة 7 قبل الحلّ:** لتجنّب استعلام DNS لأمر لن يُسمح به أصلًا. الأداء
جزء من التصميم، لا تحسين لاحق.

**لماذا الخطوة 9–11 قبل 12:** الرفض الصريح أرخص وأوضح من استنتاج المزوّد.

### ٦.٣ كاش التحليل

```go
type resolverCache struct {
    mu      sync.RWMutex
    entries map[string]cacheEntry
    ttl     time.Duration  // 300s إلزامي
}

type cacheEntry struct {
    addrs  []netip.Addr
    chain  []string
    expiry time.Time
}
```

**قواعد:**
- مفتاح الكاش = الاسم المطبَّع.
- `ttl = 300s` ثابت، غير قابل للتعديل من السياسة.
- فشل التحليل **لا يُكاش** — الفشل المؤقت يجب ألّا يُثبَّت لخمس دقائق.
- الكاش لكل `Engine`، لا عام (لتجنّب تسرّب بين سياسات).

### ٦.٤ محدّد المعدّل

```go
func (r *Rate) Allow(host string, now time.Time) bool
```

**السلوك:**
- حدّان: لكل مضيف، وعام.
- كلاهما يجب أن يسمح.
- نافذة منزلقة بسيطة (token bucket) بسعة `Burst`.
- حالات `PerHostRPS == 0` تعني **غير محدود**، لا «ممنوع».
- الرفض لا يستهلك رصيدًا.

---

## ٧. طبقات الإنفاذ — العقود

### ٧.١ L7 — البروكسي (إلزامي في M2)

```go
type Proxy struct {
    Engine  *decide.Engine
    Journal *log.Journal
}

// ServeHTTP يقرّر قبل تمرير الطلب.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request)
```

**السلوك الإلزامي:**

| الحالة | الاستجابة |
|---|---|
| مسموح | تمرير كما هو + ترويسة `X-Scope: allow` |
| مرفوض | `403` + JSON `{"error":"out-of-scope","reason":"<code>","rule":"<ref>"}` |
| `CONNECT` مرفوض | `403` ثم إغلاق فوري |
| خطأ داخلي | `500` + `{"error":"scope-engine-error"}` |

**ما يجب ألّا يفعله:**
- لا يُعدّل الترويسات عدا `X-Scope`.
- لا يقرأ الجسم (يبقى تدفقًا).
- لا يعيد المحاولة.
- لا يخزّن مؤقتًا.

**التعامل مع HTTPS:**

```go
// CONNECT: يُقيَّم الهدف من authority، لا من SNI.
if r.Method == http.MethodConnect {
    host, port, _ := net.SplitHostPort(r.Host)
    decision := p.Engine.Decide(r.Context(), host, 2)
    if decision.Verdict == decide.Deny { ... 403 ... }
}
```

**قاعدة:** في `CONNECT` نُقيّم `r.Host` فقط. لا فكّ TLS في M2. هذا يعني أن
**المسار داخل HTTPS غير مفحوص** — يُذكر في القيود.

### ٧.٢ L3 — مُحلّل DNS (M3)

```go
type Resolver struct {
    Engine *decide.Engine
    Upstream string  // مثل "1.1.1.1:53"
}

// HandleDNS يُرجع NXDOMAIN لكل ما ليس مسموحًا.
func (r *Resolver) HandleDNS(query []byte, client net.Addr) ([]byte, error)
```

**السلوك:**
- استعلام `A`/`AAAA` فقط. غيره ⇒ `REFUSED`.
- اسم مرفوض ⇒ `NXDOMAIN` (رمز 3). **لا** `0.0.0.0` — لأن الأدوات تكتشف ذلك.
- اسم مسموح ⇒ تمرير للأعلى، وإرجاع الجواب كما هو.

### ٧.٣ L4 — شيم `connect` (M4)

**Linux/macOS:** `LD_PRELOAD`/`DYLD_INSERT_LIBRARIES` على `connect(2)`.
**Windows:** WFP callout أو `Detours` — يُؤجَّل لـ M4.

**العقد:** يُقرأ الهدف من `sockaddr_in`، يُسأل المحرّك عبر socket Unix داخلي،
ثم `EACCES` أو تمرير.

**لماذا socket وليس مكتبة:** الشيم يُحمَّل في كل عملية؛ أي تخصيص ذاكرة معقّد فيه
خطر. بروتوكول نصّي بسيط: `DECIDE <ip> <port>\n` ⇒ `ALLOW\n` أو `DENY <reason>\n`.

---

## ٨. سجل الأدلة — إلزامي

### ٨.١ الشكل

```go
type Entry struct {
    Seq      uint64    `json:"seq"`
    TS       time.Time `json:"ts"`
    Target   string    `json:"target"`
    Resolved string    `json:"resolved"`
    Verdict  string    `json:"verdict"` // "allow" | "deny"
    Reason   string    `json:"reason"`
    Rule     string    `json:"rule"`
    Level    int       `json:"level"`
    PrevHash string    `json:"prev"`    // sha256 للقيد السابق
    Sig      string    `json:"sig"`     // ed25519 base64
}
```

### ٨.٢ القواعد

| القاعدة | التفصيل |
|---|---|
| إضافي فقط | `O_APPEND` فقط؛ لا `Seek`؛ لا تعديل |
| ترقيم متصل | `Seq` يبدأ من 1 ويزيد بواحد؛ فجوة = سجل مُحرَّف |
| تسلسل | `PrevHash` = SHA-256 للقيد السابق كاملًا |
| توقيع | Ed25519 على `canonical(entry minus sig)` |
| الترميز القانوني | حقول مرتّبة أبجديًا، بلا مسافات، UTF-8 |
| التوقيع لكل قيد | لا تجميع — القيد الواحد قابل للتحقق منفردًا |
| مسار افتراضي | `.scope/runs/<RFC3339>.jsonl` |

### ٨.٣ التحقق (أمر `scope verify-log`)

```go
func Verify(path string, pub ed25519.PublicKey) error
```

يتحقق من: التسلسل، `PrevHash`، التوقيع. يفشل عند أول عدم تطابق ويُبلغ `Seq`.

---

## ٩. الواجهة — العقد الكامل

### ٩.١ `scope run`

```
scope run --program <file|slug> [--level N] [--journal PATH] [--dry-run] -- <cmd> [args...]
```

| الراية | إلزامية | الافتراضي | السلوك |
|---|---|---|---|
| `--program` | ✅ | — | ملف YAML أو `hackerone/<slug>` |
| `--level` | ❌ | 1 | 0..3 |
| `--journal` | ❌ | `.scope/runs/<ts>.jsonl` | مسار السجل |
| `--dry-run` | ❌ | false | يطبع القرارات دون تنفيذ |
| `--no-proxy` | ❌ | false | يعطّل L7 |
| `--verbose` | ❌ | false | يطبع كل قرار |

**السلوك:**
1. يُحمّل السياسة؛ فشل ⇒ `exit 3` بلا تنفيذ.
2. يُفتح السجل؛ فشل ⇒ `exit 3`.
3. تُفتح الطبقات المطلوبة.
4. يُنفَّذ الأمر ببيئة معدَّلة:
   ```
   HTTP_PROXY=http://127.0.0.1:<port>
   HTTPS_PROXY=http://127.0.0.1:<port>
   REQUESTS_CA_BUNDLE=<ca>   (M3+)
   SCOPE_JOURNAL=<path>
   SCOPE_LEVEL=<level>
   ```
5. يُمرَّر `exit code` الأمر كما هو.
6. يُطبع الملخّص.

**رموز الخروج:**

| الرمز | المعنى |
|---|---|
| 0 | الأمر نجح |
| 1 | الأمر فشل (exit code الخاص به) |
| 2 | خطأ في الاستخدام |
| 3 | فشل تحميل السياسة أو السجل |
| 4 | فشل تشغيل طبقة الإنفاذ |

**قاعدة:** رمز الأمر يُحفظ دائمًا. لا يُستبدل بـ0.

### ٩.٢ `scope check`

```
scope check <url|host> [--program <file>] [--level N] [--json]
```

يقيّم هدفًا واحدًا بلا تشغيل أداة. `exit 0` مسموح، `exit 1` مرفوض، `exit 2` خطأ
استخدام.

### ٩.٣ أوامر إضافية

| الأمر | الوظيفة |
|---|---|
| `scope policy validate <file>` | تحقق فقط؛ `exit 0` أو `1` |
| `scope policy show <file>` | يطبع السياسة المُحلَّلة (مفيدة للتصحيح) |
| `scope verify-log <path>` | يتحقق من السجل؛ `exit 0` أو `1` |
| `scope journal tail` | يطبع آخر 20 قيدًا |

---

## ١٠. معالجة الأخطاء — جدول شامل

| الحالة | القرار | السجل | الخروج |
|---|---|---|---|
| ملف السياسة غير موجود | رفض الكل | `policy-missing` | 3 |
| YAML تالف | رفض الكل | `policy-invalid` + السطر | 3 |
| حقل مطلوب ناقص | رفض الكل | `policy-invalid: <field>` | 3 |
| السياسة منتهية | رفض الكل | `policy-expired` | 0* |
| نافذة مغلقة | رفض الحزم | `outside-window` | 0* |
| DNS لا يحلّ | رفض الحزمة | `unresolvable` | 0* |
| CNAME غير قابل للقراءة | رفض الحزمة | `third-party-host` | 0* |
| تجاوز المعدّل | رفض الحزمة | `rate-limited` | 0* |
| خطأ في المحرّك | رفض الحزمة | `engine-error` | 0* |
| فشل كتابة السجل | **إيقاف فوري** | — | 3 |

\* الأمر يعمل؛ الحزم تُرفض. هذا فرق جوهري: **السياسة المنتهية لا تُسقط الأداة،
بل تمنع حركتها.**

**قاعدة الذهب:** فشل السجل يُوقف كل شيء. إن لم أستطع إثبات ما فعلت، لا أفعله.

---

## ١١. مصفوفة الاختبار — إلزامية

### ١١.١ اختبارات المطابقة (٣٠ حالة على الأقل)

| # | allow | هدف | متوقع |
|---|---|---|---|
| 1 | `*.ex.com` | `a.ex.com` | ✅ |
| 2 | `*.ex.com` | `a.b.ex.com` | ❌ |
| 3 | `*.ex.com` | `ex.com` | ❌ |
| 4 | `ex.com` | `ex.com` | ✅ |
| 5 | `ex.com` | `www.ex.com` | ❌ |
| 6 | `*.EX.com` | `a.ex.com` | ✅ |
| 7 | `*.ex.com.` | `a.ex.com` | ✅ |
| 8 | `203.0.113.0/24` | `203.0.113.7` | ✅ |
| 9 | `203.0.113.0/24` | `203.0.114.7` | ❌ |
| 10 | `::/0` | `2001:db8::1` | ✅ |
| 11 | `::/0` | `203.0.113.7` | ❌ |
| 12 | allow+deny نفس الاسم | — | ❌ deny يفوز |

### ١١.٢ اختبارات القرار (٢٠ حالة)

كل صف في §6.2 يجب أن يكون له اختبار يُثبت الترتيب، خصوصًا:
- مستوى عالٍ على نطاق مسموح ⇒ رفض.
- خارج النافذة على نطاق مسموح ⇒ رفض.
- سياسة منتهية ⇒ رفض الكل حتى لو مطابق.
- استثناء صريح يتغلّب على كشف المزوّد.

### ١١.٣ اختبارات التكامل (٤ حالات — الأهم)

**الاختبار الحاكم:** حاوية معزولة، `tcpdump` على واجهة وهمية، أداة تحاول
`curl https://out-of-scope.example` ⇒ **صفر حزمة تخرج**.

```
- test_allow_lets_packet_through
- test_deny_blocks_before_socket        ← الأهم
- test_connect_deny_closes_immediately
- test_dns_returns_nxdomain
```

### ١١.٤ اختبارات السجل (٦ حالات)

- تسلسل صحيح.
- تعديل قيد ⇒ `verify-log` يفشل.
- حذف قيد ⇒ فجوة في `Seq` ⇒ يفشل.
- توقيع خاطئ ⇒ يفشل.
- كتابة متزامنة من عمليتين ⇒ لا تداخل (قفل).
- سجل فارغ ⇒ يتحقق بنجاح.

### ١١.٥ معايير التغطية

| المعيار | الحدّ |
|---|---|
| تغطية السطور في `internal/decide` | **≥ 95%** |
| تغطية السطور إجمالًا | **≥ 85%** |
| كل `Reason` مغطّى باختبار | **100%** |
| كل صف في §10 مغطّى | **100%** |

---

## ١٢. حدود الأداء — ملزمة

| المقياس | الحدّ | كيف يُقاس |
|---|---|---|
| قرار من كاش | **< 1 ms** | `BenchmarkDecideCached` |
| قرار مع DNS | **< 30 ms** | `BenchmarkDecideResolve` |
| إنتاجية البروكسي | **> 5000 rps** | `BenchmarkProxy`, 100 اتصال |
| ذاكرة | **< 50 MB** | `go test -benchmem` |
| إقلاع | **< 300 ms** | `BenchmarkBootstrap` |

**قاعدة:** إن تجاوز القرار 1ms يصبح عبئًا فيُعطَّل. الأداء شرط قبول لا تحسين.

---

## ١٣. معايير القبول — البوابة النهائية

المشروع **غير مكتمل** حتى تتحقق كل هذه:

### الوظيفة

- [ ] `scope run` ينفّذ أمرًا حقيقيًا ويعيد رمز خروجه.
- [ ] حزمة إلى نطاق خارج `allow` **لا تخرج** — مُثبت بـ`tcpdump`.
- [ ] `deny` يتغلّب على `allow` في كل الحالات.
- [ ] `status.example.com` → `*.statuspage.io` يُرفض تلقائيًا.
- [ ] استثناء صريح يتغلّب على كشف المزوّد.
- [ ] سياسة منتهية ترفض الكل ولا تُسقط الأداة.
- [ ] النافذة الزمنية تُطبَّق بالمنطقة الزمنية الصحيحة.

### الأمان

- [ ] كل مسار فشل ينتهي برفض.
- [ ] لا مسار يسمح عند الشك.
- [ ] فشل السجل يوقف التنفيذ.
- [ ] لا صلاحيات إدارية مطلوبة في M2.
- [ ] لا اعتماد على مكتبة بروكسي خارجية.

### الجودة

- [ ] `go vet ./...` نظيف.
- [ ] `golangci-lint run` بلا تحذير.
- [ ] `go test -race ./...` نظيف.
- [ ] التغطية تحقق §11.5.
- [ ] كل دالة عامة لها تعليق يبدأ باسمها.

### التوثيق

- [ ] `README` يشرح: ما تفعله، ما لا تفعله، الحدود المعروفة.
- [ ] كل `Reason` مشروح في `docs/reasons.md`.
- [ ] مثال سياسة صالح وآخر خاطئ في `testdata/`.

---

## ١٤. ترتيب البناء — إلزامي

لا يُبدأ بمرحلة قبل اكتمال سابقتها.

| المرحلة | المخرجات | معيار الخروج |
|---|---|---|
| **M1.1** | `policy` + `decide` + اختبارات §11.1–11.2 | 50 اختبارًا تمر، تغطية ≥95% |
| **M1.2** | `log` + `verify-log` | 6 اختبارات سجل تمر |
| **M1.3** | `cli run` مع `--dry-run` فقط | يطبع قرارات صحيحة بلا تنفيذ |
| **M2.1** | `enforce/proxy` (L7) | اختبار التكامل: صفر حزمة |
| **M2.2** | `cli run` حقيقي | الأمر يعمل ويحفظ رمز الخروج |
| **M3** | `enforce/dns` (L3) | NXDOMAIN مثبت |
| **M4** | `enforce/connect` (L4) | Linux أولًا |

**قاعدة:** بعد كل مرحلة، `go test -race ./...` يجب أن يمر قبل الانتقال.

---

## ١٥. الحالات الحرجة — يجب اختبارها صراحةً

| # | الحالة | السلوك المطلوب |
|---|---|---|
| 1 | `allow: ["*"]` | تحذير عند التحميل؛ يعمل لكن يُسجَّل |
| 2 | اسم فيه أحرف كبيرة | يُوحَّد، لا يُرفض |
| 3 | اسم فيه `..` | يُرفض كـ`policy-invalid` |
| 4 | CIDR بسابقة غير صالحة | `policy-invalid` |
| 5 | ساعة النظام في المستقبل | `policy-expired` (فشل مغلق) |
| 6 | نافذة `00:00-00:00` | تعني **يوم كامل** لا صفرًا |
| 7 | `per_host_rps: 0` | غير محدود، لا ممنوع |
| 8 | DNS يُرجع IPv6 فقط | يُقيَّم مقابل `allow` بنفس الطريقة |
| 9 | أمر ينتهي إشارة | يُمرَّر 128+signal |
| 10 | سجل على قرص ممتلئ | إيقاف فوري، `exit 3` |
| 11 | عمليتان تكتبان السجل | قفل ملف، بلا تداخل |
| 12 | سياسة تتغيّر أثناء التشغيل | تُقرأ عند الإقلاع فقط في M1–M2 |

---

## ١٦. ما يجب أن يُسلَّم مع الكود

| الملف | المحتوى |
|---|---|
| `README.md` | الاستخدام، الحدود المعروفة، مثال كامل |
| `docs/SPEC.md` | هذا الملف |
| `docs/reasons.md` | كل رمز رفض: متى يظهر، ماذا يعني، كيف يُصلَح |
| `docs/limits.md` | ما لا تحميه الطبقة، صراحةً |
| `testdata/policy_valid.yaml` | مثال يعمل فورًا |
| `testdata/policy_bad_syntax.yaml` | مثال يفشل كما هو متوقع |
| `CHANGELOG.md` | يبدأ بـ`0.1.0` |

---

## ١٧. القيد الأخلاقي — جزء من المواصفة لا ملحق

كل تقرير يُنتجه المشروع **يجب** أن يحتوي السطر:

> `Authorised use only. This tool enforces a policy you supplied; it does not verify your authorisation.`

ولا يُسمح بإضافة راية تخفيه. أداة تدّعي الامتثال يجب ألّا تسمح بإخفاء تنبيهه.

---

**نهاية المواصفة.** أي غموض متبقٍ يُحلّ لصالح: **الرفض**، **الوضوح**، **الأداء** —
بهذا الترتيب.
