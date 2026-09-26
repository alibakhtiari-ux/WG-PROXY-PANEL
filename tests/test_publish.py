#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""گاردِ ابزارِ انتشار (publish/) — بدونِ ساختنِ واقعیِ شاخه.

خودِ make-public.sh پیش از کامیت گاردهای سنگین را می‌زند (اسکنِ شناسه،
اجرای تست‌ها از داخلِ درختِ عمومی، py_compile). این فایل چیزهایی را می‌گیرد
که **پیش از** رسیدن به آنجا خراب می‌شوند و اجرای اسکریپت را بی‌فایده
می‌کنند:

  ۱) ورودیِ فهرستِ سفید که دیگر وجود ندارد (مسیر عوض شده)
  ۲) فهرستِ شناسه‌های خصوصیِ خالی ⇒ گاردِ نشت بی‌صدا هیچ نمی‌سنجد
  ۳) ارجاعِ README ِ عمومی به فایلی که منتشر نمی‌شود
  ۴) دگرگونیِ Dockerfile که فرضش دیگر برقرار نیست

⚠️ خودِ publish/ منتشر نمی‌شود؛ در مخزنِ عمومی این تست skip می‌شود.
"""
import os
import re
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PUB = os.path.join(REPO, "publish")


def _read(*parts):
    with open(os.path.join(*parts), "r", encoding="utf-8") as f:
        return f.read()


def _entries(text):
    """(ورودی‌های نگه‌داشتنی، ورودی‌های حذفی) — همان تفسیرِ make-public.sh."""
    keep, drop = [], []
    for line in text.split("\n"):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        (drop if line.startswith("-") else keep).append(line.lstrip("-"))
    return keep, drop


class PublishToolingTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not os.path.isdir(PUB):
            raise unittest.SkipTest("پوشه‌ی publish/ نیست — مخزنِ عمومی")

    def test_filelist_entries_exist(self):
        keep, drop = _entries(_read(PUB, "filelist.txt"))
        self.assertTrue(keep, "فهرستِ سفید خالی است")
        for e in keep + drop:
            self.assertTrue(
                os.path.exists(os.path.join(REPO, e)),
                "ورودیِ فهرستِ سفید وجود ندارد: %s" % e)

    def test_filelist_excludes_the_operational_layer(self):
        keep, _ = _entries(_read(PUB, "filelist.txt"))
        forbidden = ("CLAUDE.md", "README.fa.md", "CHANGELOG.md", ".claude",
                     "ansible", "online", "airgap", "scripts", "publish")
        for e in keep:
            head = e.strip("/").split("/")[0]
            self.assertNotIn(head, forbidden,
                             "لایه‌ی عملیاتی در فهرستِ سفید: %s" % e)
            self.assertFalse(e.endswith(".html"),
                             "سندِ HTML در فهرستِ سفید: %s" % e)

    def test_private_identifier_list_is_not_empty(self):
        """گاردِ خالی بدترین حالت است: سبز می‌ماند و هیچ نمی‌سنجد."""
        pats = [ln.split("#", 1)[0].strip()
                for ln in _read(PUB, "private-identifiers.txt").split("\n")]
        pats = [p for p in pats if p]
        self.assertGreaterEqual(len(pats), 3,
                                "فهرستِ شناسه‌های خصوصی مشکوکانه کوتاه است")
        for p in pats:
            try:
                re.compile(p)
            except re.error as e:
                self.fail("الگوی نامعتبر در فهرستِ شناسه‌ها: %s (%s)" % (p, e))

    def test_public_readme_links_only_to_published_paths(self):
        """README ِ عمومی نباید به فایلی لینک بدهد که منتشر نمی‌شود."""
        keep, drop = _entries(_read(PUB, "filelist.txt"))
        body = "\n".join(_read(PUB, s) for s in self.READMES.values())
        for _, href in re.findall(r"\[([^\]]+)\]\(([^)]+)\)", body):
            if href.startswith(("http", "#", "mailto")):
                continue
            path = href.split("#")[0].rstrip("/")
            self.assertNotIn(path, drop, "لینک به فایلِ حذف‌شده: %s" % href)
            # سه حالتِ معتبر: خودِ ورودی · زیرِ یک ورودیِ پوشه‌ای · پوشه‌ای
            # که دستِ‌کم یک ورودی داخلش است (نمونه: لینک به `deploy/` در
            # حالی که فهرست فایل‌های deploy/* را تک‌به‌تک نام می‌برد).
            published = any(
                path == k.rstrip("/")
                or path.startswith(k.rstrip("/") + "/")
                or k.rstrip("/").startswith(path + "/")
                for k in keep + list(self.READMES))
            self.assertTrue(published,
                            "README ِ عمومی به مسیرِ منتشرنشده لینک داده: %s"
                            % href)
            # README های ترجمه را ژنراتور از publish/ می‌سازد؛ منبعشان را بسنج
            real = (os.path.join(PUB, self.READMES[path]) if path in self.READMES
                    else os.path.join(REPO, path))
            self.assertTrue(os.path.exists(real),
                            "مقصدِ لینک وجود ندارد: %s" % href)

    # README ِ عمومی به چهار زبان: publish/README.public[.<L>].md ⇒ README[.<L>].md
    READMES = {"README.md": "README.public.md",
               "README.fa.md": "README.public.fa.md",
               "README.ru.md": "README.public.ru.md",
               "README.zh-CN.md": "README.public.zh-CN.md"}

    @staticmethod
    def _fences(body):
        return re.findall(r"^```[a-z]*\n.*?^```$", body, re.S | re.M)

    @staticmethod
    def _gh_slug(heading):
        """الگوریتمِ لنگرِ گیت‌هاب برای عنوانِ لاتین (کوچک، حذفِ نشانه‌ها،
        فاصله ⇒ خط‌تیره). برای عنوانِ غیرلاتین به آن تکیه نمی‌کنیم — ترجمه‌ها
        لنگرِ صریحِ <a id> دارند."""
        s = re.sub(r"[^\w\- ]", "", heading.strip().lower())
        return s.replace(" ", "-")

    def test_all_four_readmes_exist_and_are_generated(self):
        sh = _read(PUB, "make-public.sh")
        for src in self.READMES.values():
            self.assertTrue(os.path.isfile(os.path.join(PUB, src)), src)
        m = re.search(r'README_LANGS="([^"]+)"', sh)
        self.assertIsNotNone(m)
        assert m is not None
        self.assertEqual(sorted(m.group(1).split()), ["fa", "ru", "zh-CN"])

    def test_translations_keep_identical_commands(self):
        """خانواده‌ی «ترجمه‌ای که دستور را هم عوض کرد»: هر بلوکِ کد در هر
        چهار زبان باید بایت‌به‌بایت همان نسخه‌ی انگلیسی باشد و به همان ترتیب."""
        en = self._fences(_read(PUB, "README.public.md"))
        self.assertGreater(len(en), 5)
        for pub, src in self.READMES.items():
            self.assertEqual(self._fences(_read(PUB, src)), en,
                             "%s بلوکِ کدِ متفاوت با انگلیسی دارد" % pub)

    def test_translations_have_the_same_structure(self):
        def shape(body):
            return [len(h) for h in re.findall(r"^(#{2,3}) ", body, re.M)]
        en = shape(_read(PUB, "README.public.md"))
        for pub, src in self.READMES.items():
            self.assertEqual(shape(_read(PUB, src)), en,
                             "%s ساختارِ عنوان‌هایش با انگلیسی نمی‌خواند" % pub)

    def test_language_switcher_links_every_other_language(self):
        for pub, src in self.READMES.items():
            body = _read(PUB, src)
            head = body[:body.index("</div>")]
            links = set(re.findall(r"\]\((README[\w.\-]*\.md)\)", head))
            self.assertEqual(links, set(self.READMES) - {pub},
                             "انتخابگرِ زبانِ %s ناقص است" % pub)

    def test_every_toc_link_resolves(self):
        """لنگرِ خودکارِ گیت‌هاب برای عنوانِ فارسی/روسی/چینی قابلِ اتکا نیست؛
        پس ترجمه‌ها <a id> ِ صریح دارند و هر لینکِ #… باید به یکی برسد."""
        for pub, src in self.READMES.items():
            body = _read(PUB, src)
            targets = set(re.findall(r'<a id="([^"]+)"></a>', body))
            targets |= {self._gh_slug(h) for h in
                        re.findall(r"^#{1,6} (.+)$", body, re.M)}
            for frag in re.findall(r"\]\(#([^)]+)\)", body):
                self.assertIn(frag, targets,
                              "%s: لینکِ #%s مقصد ندارد" % (pub, frag))

    def test_readme_command_facts_match_the_code(self):
        """ادعاهای عددی/دستوریِ README باید با کد بخوانند، نه با حافظه."""
        body = _read(PUB, "README.public.md")
        src = _read(REPO, "wg_panel.py")
        self.assertIn("SAMPLE_INTERVAL = 2.0", src)          # «every 2 seconds»
        self.assertIn("return len(attempts) < 5", src)        # «5 attempts per minute»
        self.assertIn('BUILTIN_ROLES = ("admin", "viewer")', src)
        self.assertIn('LANGS = ("fa", "en", "ru", "zh")', src)
        self.assertIn("1 minute\n  to 24 hours", body)
        self.assertRegex(src, r"\(1 to 1440\)")               # ۱ تا ۱۴۴۰ دقیقه
        n_cmds = len(re.findall(r'\("[a-z]+", "[^"]+"\)', src[
            src.index("def bot_setcommands"):src.index("BOT = TelegramBot()")]))
        self.assertEqual(n_cmds, 18, "تعدادِ دستورهای ربات عوض شد — README را هم")
        self.assertIn("**18 commands**", body)
        n_ev = src[src.index("ALERT_EVENTS = ("):src.index("ALERT_EVENT_KEYS")
                   ].count('("')
        self.assertEqual(n_ev, 12, "تعدادِ انواعِ هشدار عوض شد — README را هم")
        self.assertIn("**12 kinds of alerts**", body)
        for key in re.findall(r"^\| `(\w+)`", body, re.M):
            if key in ("wg_panel", "docker", "deploy", "tests", "fonts", "qr"):
                continue
            self.assertIn('"%s"' % key, src,
                          "کلیدِ پیکربندیِ README در کد نیست: %s" % key)

    # آدرس‌های کمکِ مالی — هر حرفِ اشتباه یعنی پولِ گم‌شده. اینجا عمداً یک
    # نسخه‌ی دوم است تا ویرایشِ ناخواسته‌ی هر README قرمز شود.
    DONATION = ("TV4R2i7yQxzEVSzZEXwBJqfhDavifaGwMt",            # USDT TRC20
                "0x5631398273a7283d543A62336eD090101FF3D449",    # BSC (EIP-55)
                "bc1qjnmmqs5c57shld3ka90vcle4scxhszevehj4y3")    # BTC bech32

    def test_donation_addresses_are_valid_and_identical_everywhere(self):
        import hashlib
        trx, _bsc, btc = self.DONATION
        # TRON: Base58Check، بایتِ نسخه 0x41
        A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        n = 0
        for c in trx:
            n = n * 58 + A.index(c)
        b = n.to_bytes(25, "big")
        self.assertEqual(b[0], 0x41)
        self.assertEqual(hashlib.sha256(hashlib.sha256(b[:21]).digest())
                         .digest()[:4], b[21:], "checksum ِ آدرسِ TRC20")
        # Bitcoin: bech32 (BIP-173)
        CH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
        hrp, data = btc.split("1", 1)
        c = 1
        for v in ([ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]
                  + [CH.index(x) for x in data]):
            top = c >> 25
            c = (c & 0x1ffffff) << 5 ^ v
            for i, g in enumerate((0x3b6a57b2, 0x26508e6d, 0x1ea119fa,
                                   0x3d4233dd, 0x2a1462b3)):
                c ^= g if (top >> i) & 1 else 0
        self.assertEqual(c, 1, "checksum ِ آدرسِ BTC")
        # هر آدرس در هر چهار README دقیقاً یک بار، و فقط داخلِ بلوکِ کد
        for pub, src in self.READMES.items():
            body = _read(PUB, src)
            fences = "\n".join(self._fences(body))
            for addr in self.DONATION:
                self.assertEqual(body.count(addr), 1, "%s: %s" % (pub, addr))
                self.assertIn(addr, fences, "%s: آدرس بیرونِ بلوکِ کد" % pub)

    def test_dockerfile_transform_assumption_holds(self):
        """اسکریپت ۴ ارجاع به ansible/ را به deploy/ می‌برد و اگر تعداد
        فرق کند می‌میرد. اینجا همان فرض را زودتر می‌سنجیم — و مهم‌تر،
        اینکه فایلِ مقصد در deploy/ واقعاً هست و بایت‌به‌بایت یکی است."""
        df = _read(REPO, "docker", "Dockerfile")
        srcs = re.findall(r"(ansible/roles/wg-panel/files/(\S+))", df)
        self.assertEqual(len(srcs), 4,
                         "تعدادِ ارجاعِ Dockerfile به ansible/ عوض شده — "
                         "دگرگونیِ make-public.sh را هم‌گام کن")
        import hashlib
        for full, name in srcs:
            dep = os.path.join(REPO, "deploy", name)
            self.assertTrue(os.path.isfile(dep),
                            "دگرگونی به deploy/%s اشاره می‌کند ولی نیست" % name)
            h = lambda p: hashlib.sha256(open(p, "rb").read()).hexdigest()
            self.assertEqual(h(os.path.join(REPO, full)), h(dep),
                             "deploy/%s با نسخه‌ی ansible یکی نیست — "
                             "درختِ عمومی فایلِ متفاوتی می‌گیرد" % name)

    def test_verify_backup_transform_assumption_holds(self):
        """اسکریپت ۳ ارجاعِ myserver- را در verify-backup خنثی می‌کند و اگر
        تعداد فرق کند می‌میرد؛ همان فرض اینجا زودتر سنجیده می‌شود."""
        vb = _read(REPO, "deploy", "wg-panel-verify-backup.sh")
        self.assertEqual(vb.count("myserver-"), 3,
                         "تعدادِ ارجاعِ verify-backup به myserver- عوض شده — "
                         "دگرگونیِ make-public.sh را هم‌گام کن")

    def test_deployment_short_name_is_neutralized_and_guarded(self):
        """تصمیمِ کاربر: هیچ «myserver» ای در نسخه‌ی عمومی نماند. دگرگونی باید
        پیش از گاردهای نشت بیاید و خودش یک گاردِ صفر-باقی‌مانده داشته باشد —
        جایگزینیِ بی‌گارد با اولین نامِ تازه (مثلاً myserverw2) بی‌صدا نشت می‌کرد."""
        sh = _read(PUB, "make-public.sh")
        i_sub = sh.find("s#myserver#myserver#g")
        self.assertGreater(i_sub, 0, "جایگزینیِ عامِ myserver نیست")
        self.assertIn("«myserver» پس از دگرگونی ماند", sh)
        self.assertLess(i_sub, sh.find("گاردهای نشت (الگوها"),
                        "دگرگونی باید پیش از گاردهای نشت بیاید")
        # خاص‌ترین اول: اگر myserver پیش از wg-panel بیاید، issuer به
        # «wg-panel-myserver» تبدیل می‌شود نه «wg-panel»
        self.assertLess(sh.find("s#wg-panel#"), i_sub)
        self.assertLess(sh.find("s#myserver#"), i_sub)
        # در worktree، .git یک *فایل* است با مسیرِ مخزن (…wg-panel…)؛
        # --exclude-dir آن را نمی‌گیرد و جایگزینی gitdir را می‌شکست.
        for ln in sh.split("\n"):
            if "grep -rIil 'myserver'" in ln:
                self.assertIn("--exclude=.git ", ln,
                              "فایلِ .git ِ worktree باید مستثنا باشد: " + ln)

    def test_commit_metadata_is_part_of_the_leak_surface(self):
        """خانواده‌ی «نشت بیرون از درخت»: نام و ایمیلِ نویسنده‌ی کامیت و تگ
        هم منتشر می‌شوند. پیش‌فرضِ گیت روی مک name@<کامپیوتر>.local است و
        اسکنِ درخت آن را نمی‌بیند — پس هویت باید صریح باشد و متادیتا هم
        با همان فهرستِ شناسه‌ها سنجیده شود."""
        sh = _read(PUB, "make-public.sh")
        for var in ("GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL",
                    "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL"):
            self.assertRegex(sh, r"export[^\n]*\b%s=" % var,
                             "%s صریح export نشده" % var)
        m = re.search(r'GIT_AUTHOR_EMAIL="([^"]+)"', sh)
        self.assertIsNotNone(m, "GIT_AUTHOR_EMAIL مقدارِ صریح ندارد")
        assert m is not None
        self.assertNotRegex(m.group(1), r"\.local$")
        self.assertIn("متادیتای کامیت نشت دارد", sh)
        self.assertIn('"$IDENT"', sh.split("متادیتای کامیت نشت دارد")[1][:200])

    def test_real_owner_identifiers_stay_out_of_tests(self):
        """شناسه‌ی تلگرامِ مالک و نامِ حسابِ واقعیِ سرور یک بار در تست‌ها
        بودند و به نسخه‌ی عمومی می‌رفتند. هر شناسه‌ی فهرستِ خصوصی نباید در
        هیچ فایلِ tests/ ای باشد که منتشر می‌شود."""
        pats = [ln.split("#", 1)[0].strip() for ln in
                _read(PUB, "private-identifiers.txt").split("\n")]
        pats = [re.compile(p) for p in pats if p]
        tdir = os.path.join(REPO, "tests")
        for name in os.listdir(tdir):
            if not name.endswith(".py") or name == "test_publish.py":
                continue
            body = _read(tdir, name)
            for p in pats:
                self.assertIsNone(p.search(body),
                                  "tests/%s شناسه‌ی خصوصی دارد: %s"
                                  % (name, p.pattern))

    def test_version_is_semver(self):
        """publish/VERSION نشانِ انتشار است، نه شمارنده‌ی بیلد.

        شناسه‌ی دقیقِ هر بیلد با build-metadata می‌آید (1.0.0+<هشِ پنل>)،
        پس این عدد فقط وقتی بالا می‌رود که انتشارِ تازه‌ای در کار باشد.
        """
        v = _read(PUB, "VERSION").strip()
        self.assertRegex(v, r"^\d+\.\d+\.\d+$",
                         "VERSION باید semver باشد، دیده شد: %r" % v)

    def test_post_commit_hook_cannot_recurse(self):
        """هوک باید خودش را هنگامِ اجرای ژنراتور خاموش کند.

        make-public.sh داخلِ یک worktree کامیت می‌کند و worktreeها همان
        .git/hooks را به اشتراک می‌گذارند — بدونِ گارد، حلقه‌ی بی‌پایان.
        """
        h = _read(PUB, "git-hooks", "post-commit")
        self.assertIn("WG_PUBLISH_RUNNING", h, "گاردِ ضدِ بازگشت نیست")
        self.assertIn("public-build-", h,
                      "هوک باید روی شاخه‌های موقتِ ژنراتور هم ساکت بماند")
        self.assertIn("filelist.txt", h,
                      "هوک باید فقط وقتی کار کند که مجموعه‌ی عمومی لمس شده")

    def test_post_commit_hook_sees_merge_commits(self):
        """`git diff-tree -r <merge>` صفر فایل می‌دهد — هوک بی‌صدا رد می‌شد.

        دقیقاً رخ داد: ادغامِ i18n-4lang در main با ۳۸ فایلِ عوض‌شده، و هوک
        هیچ نگفت. آن‌بار public اتفاقی هم‌گام بود چون از همان محتوا ساخته
        شده بود؛ در حالتِ کلی نبود. `diff HEAD^ HEAD` هر دو حالت را می‌گیرد.
        """
        raw = _read(PUB, "git-hooks", "post-commit")
        # 🪤 کامنت‌ها کنار گذاشته می‌شوند: نخستین «diff-tree» در فایل داخلِ
        # توضیحی است که *دربارهٔ* همین تله نوشته شده، و سنجهٔ ترتیب روی متنِ
        # خام به همان نثر گیر می‌کرد نه به کد. همان خانواده‌ای که گاردِ
        # regex ِ ممیزی و گاردِ نامِ میزبان را هم زمین زد.
        h = "\n".join(l for l in raw.split("\n")
                      if not l.lstrip().startswith("#"))
        self.assertIn("diff --name-only HEAD^ HEAD", h,
                      "هوک باید first-parent diff بگیرد تا merge را هم ببیند")
        # diff-tree مجاز است — ولی فقط به‌عنوانِ fallback ِ کامیتِ بی‌والد،
        # یعنی پشتِ گاردِ «آیا HEAD^ وجود دارد». اگر بی‌گارد باشد، دوباره
        # مسیرِ اصلی شده و کوریِ merge برگشته است.
        if "diff-tree" in h:
            self.assertIn("rev-parse --verify --quiet HEAD^", h,
                          "diff-tree باید پشتِ گاردِ «والد دارد؟» باشد")
            self.assertLess(
                h.index("diff --name-only HEAD^ HEAD"), h.index("diff-tree"),
                "مسیرِ اصلی باید first-parent diff باشد، نه diff-tree")

    def test_hook_installer_checks_exec_bit(self):
        """بیتِ exec باربر است: بدونش گیت هوک را **بی‌صدا** نادیده می‌گیرد،
        یعنی بازسازیِ خودکار خاموش می‌شود و هیچ‌چیز قرمز نمی‌شود."""
        s = _read(PUB, "install-git-hooks.sh")
        self.assertIn("-x ", s, "نصاب باید بیتِ اجرا را بسنجد")
        self.assertIn("install -m755", s, "نصاب باید هوک را اجراپذیر بگذارد")

    # ── هوکِ post-commit (پلنِ ۰۴۸) ────────────────────────────────────

    def test_hook_does_not_write_its_log_to_a_fixed_tmp_path(self):
        """لاگِ هوک نباید در مسیرِ ثابتِ /tmp بنشیند.

        محتوایش خروجیِ گاردهای نشت است: نامِ فایل‌های نشت‌کرده و
        الگوهای خصوصی‌ای که به آن‌ها خورده‌اند. کلِ نکته‌ی
        private-identifiers.txt این است که آن رشته‌ها نباید بیرون
        بروند؛ لاگی که فهرستشان می‌کند خودش نقضش است. ضمناً مسیرِ
        ثابت در /tmp هدفِ symlink است.
        """
        src = _read(PUB, "git-hooks", "post-commit")
        body = "\n".join(l for l in src.split("\n")
                         if not l.lstrip().startswith("#"))
        self.assertNotRegex(body, r">\s*/tmp/",
                            "هوک هنوز در مسیرِ ثابتِ /tmp می‌نویسد")
        self.assertIn("rev-parse --git-dir", body,
                      "لاگ داخلِ .git ِ همین مخزن نوشته نمی‌شود")
        self.assertIn("chmod 700", body, "پوشه‌ی لاگ مود نمی‌گیرد")

    def test_hook_prunes_stale_worktrees(self):
        """ورک‌تریِ ثبت‌شده‌ی رهاشده باید هرس شود.

        ℹ️ خودِ ژنراتور `trap cleanup EXIT` با `worktree remove` دارد،
        پس مسیرهای عادیِ خطا پوشش دارند — این فقط حالتِ kill-9/کرش را
        می‌گیرد.
        """
        body = _read(PUB, "git-hooks", "post-commit")
        self.assertIn("worktree prune", body)

    def test_the_generator_still_cleans_up_its_own_worktree(self):
        """ادعای بالا به این تکیه دارد — پس همین‌جا پینش کن."""
        body = _read(PUB, "make-public.sh")
        self.assertIn("worktree remove --force", body)
        self.assertIn("trap cleanup EXIT", body)

    def test_hook_keeps_its_three_recorded_fixes(self):
        """سه رفعِ ثبت‌شده‌ی هوک نباید حین تمیزکاری از بین بروند.

        گاردِ ضدِ بازگشت، unset ِ متغیرهای گیت، و diff HEAD^ HEAD
        به‌جای diff-tree — آخری چون diff-tree روی کامیتِ merge صفر
        فایل می‌دهد و هوک یک بار واقعاً کور شد. این فایل دقیقاً همان
        نوع کامیتِ «تمیزکاری» را جذب می‌کند که آن سه را می‌برد.
        """
        body = _read(PUB, "git-hooks", "post-commit")
        self.assertIn("WG_PUBLISH_RUNNING", body)
        self.assertIn("GIT_INDEX_FILE", body)
        self.assertIn("diff --name-only HEAD^ HEAD", body)
        self.assertNotIn("diff-tree --no-commit-id --name-only -r HEAD^", body)


    def test_generator_never_adds_a_remote(self):
        """قیدِ مطلقِ مخزن: هیچ ریموتی، هیچ push ای."""
        sh = _read(PUB, "make-public.sh")
        for bad in ("git remote add", "git push", "gh repo create"):
            self.assertNotIn(bad, sh,
                             "ابزارِ انتشار نباید %r داشته باشد" % bad)


    # ── گاردِ لایه‌ی عملیاتی: خلاصه باید درباره‌ی «چیزی» بگوید، نه «آخرین عنصر»

    @staticmethod
    def _leak_block():
        """بلاکِ گاردِ لایه‌ی عملیاتی را از خودِ اسکریپت بیرون می‌کشد.

        عمداً کپی نمی‌شود: کپی از اصل جدا می‌افتد و بعد هیچ‌چیز را نمی‌سنجد.
        لنگرها معنایی‌اند (شمارنده و متنِ خطِ سبز)، نه شماره‌ی خط.
        """
        lines = _read(PUB, "make-public.sh").split("\n")
        starts = [i for i, l in enumerate(lines) if l.strip() == "op_leak=0"]
        ends = [i for i, l in enumerate(lines)
                if "هیچ پوشه/سندِ عملیاتی‌ای وارد نشد" in l]
        if len(starts) != 1 or len(ends) != 1 or ends[0] < starts[0]:
            return None
        return "\n".join(lines[starts[0]:ends[0] + 1])

    def test_leak_summary_does_not_depend_on_the_loop_variable(self):
        """خطِ سبزِ خلاصه نباید به متغیرِ بازمانده‌ی حلقه تکیه کند.

        پیش از این، پس از پایانِ حلقه $f آخرین عنصر (publish) بود و خطِ
        سبز عملاً می‌پرسید «publish نشت کرد؟» نه «چیزی نشت کرد؟». نشتِ
        هر عنصرِ دیگری هر دو خطِ قرمز و سبز را با هم چاپ می‌کرد.
        """
        src = _read(PUB, "make-public.sh")
        # کامنت‌ها را بیرون بگذار: این مخزن دو بار گاردی داشته که به‌جای کد،
        # کامنتِ توضیح‌دهنده‌ی همان دام را می‌گرفت.
        body = "\n".join(l for l in src.split("\n")
                         if not l.lstrip().startswith("#"))
        self.assertNotIn('[ -e "$WT/$f" ] ||', body,
                         "خلاصه هنوز روی $f ِ بازمانده از حلقه تصمیم می‌گیرد")
        self.assertIn("op_leak=0", body, "شمارنده‌ی مستقلِ نشت پیدا نشد")

    def test_leak_guard_never_prints_green_and_red_together(self):
        """در هیچ حالتی نباید هم‌زمان «نشت کرد» و «هیچ نشتی» چاپ شود.

        حالتِ تعیین‌کننده نشتِ چیزی **جز آخرین عنصرِ فهرست** است: نشتِ
        خودِ `publish` روی کدِ خراب هم درست رفتار می‌کرد و همین پنهانش
        کرده بود.
        """
        import pathlib
        import subprocess
        import tempfile
        block = self._leak_block()
        self.assertIsNotNone(
            block, "بلاکِ گارد استخراج نشد — لنگرها عوض شده‌اند؟")
        for leak in (None, "CLAUDE.md", "ansible", "publish"):
            with tempfile.TemporaryDirectory() as d:
                if leak == "CLAUDE.md":
                    pathlib.Path(d, leak).touch()
                elif leak:
                    pathlib.Path(d, leak).mkdir()
                out = subprocess.run(
                    ["bash", "-c", 'set -Eeuo pipefail\nWT="$1"; fail=0\n' + block,
                     "_", d],
                    capture_output=True, text=True).stdout
                with self.subTest(leak=leak):
                    red = "نشت کرد" in out
                    green = "هیچ پوشه" in out
                    self.assertNotEqual(
                        red, green,
                        "خروجیِ متناقض برای leak=%s:\n%s" % (leak, out))
                    self.assertEqual(red, leak is not None,
                                     "نشتِ %s تشخیص داده نشد:\n%s" % (leak, out))


class PublishExecutionTests(unittest.TestCase):
    """اجرای واقعیِ make-public.sh در کلونِ یک‌بارمصرف.

    نُه گاردِ موجود سورس را **می‌خوانند**. باگی که پلنِ ۰۱۲ ثبت کرده از
    کنارِ هر نُه‌تا رد شد: خطِ خلاصه به $f ِ بازمانده از حلقه تکیه
    داشت، پس نشتِ هر عنصری جز آخری، قرمز و سبز را با هم چاپ می‌کرد.
    گاردِ متنی این را نمی‌بیند؛ اجرا با نشتِ کاشته‌شده بلافاصله می‌بیند.

    🪤 **دامِ بازگشت.** اسکریپت پیش از هر کاری کلِ سوئیت را می‌راند —
    یعنی همین کلاس را هم، داخلِ کلون. بدونِ نگهبان، هر اجرا یک کلونِ
    تازه می‌سازد و تا ته می‌رود. `NESTED` همان نگهبان است: ‏`_run` آن
    را در محیطِ فرزند می‌گذارد و کلاس در حضورش skip می‌شود.
    """

    NESTED = "WG_PANEL_PUBLISH_EXEC_NESTED"

    @classmethod
    def setUpClass(cls):
        if os.environ.get(cls.NESTED):
            raise unittest.SkipTest("اجرای تودرتو — از بازگشت جلوگیری شد")
        if not os.path.isdir(PUB):
            raise unittest.SkipTest("پوشه‌ی publish/ نیست — مخزنِ عمومی")
        import subprocess
        if subprocess.run(["git", "-C", REPO, "rev-parse", "HEAD"],
                          capture_output=True).returncode != 0:
            raise unittest.SkipTest("مخزنِ گیت نیست")

    def setUp(self):
        import subprocess
        import tempfile
        self.tmp = tempfile.mkdtemp(prefix="wgpanel-pub-")
        self.clone = os.path.join(self.tmp, "repo")
        # --no-hardlinks یعنی کپیِ کامل: با hardlink، آبجکتی که در کلون
        # نوشته شود می‌تواند به مخزنِ اصلی برسد.
        r = subprocess.run(["git", "clone", "--no-hardlinks", "--quiet",
                            REPO, self.clone], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, "کلون شکست: %s" % r.stderr)
        # شاخه‌ی محلیِ public **به‌ساخت** هم‌گام می‌شود، نه با کپیِ
        # origin/public. اتکا به وضعیتِ شاخه‌ی مخزنِ واقعی یعنی تست هر بار
        # که public عقب باشد — مثلاً درست بعد از یک کامیت — به دلیلِ اشتباه
        # قرمز می‌شود. --check موضوعِ کامیتِ آخرِ public را با
        # «VERSION+sha12(wg_panel.py)» می‌سنجد، پس همان را می‌سازیم.
        subprocess.run(["git", "-C", self.clone, "branch", "-qD", "public"],
                       capture_output=True)
        subprocess.run(["git", "-C", self.clone, "branch", "-f", "public",
                        self._synth_public_commit()], capture_output=True)
        # هیچ ریموتی نماند — قاعده‌ی مطلقِ مخزن، و بیمه در برابرِ
        # اسکریپتی که روزی push اضافه کند.
        subprocess.run(["git", "-C", self.clone, "remote", "remove", "origin"],
                       capture_output=True)

    def tearDown(self):
        import shutil
        shutil.rmtree(getattr(self, "tmp", ""), ignore_errors=True)

    def _git(self, *args):
        import subprocess
        return subprocess.run(["git", "-C", self.clone] + list(args),
                              capture_output=True, text=True).stdout.strip()

    def _synth_public_commit(self):
        """کامیتی می‌سازد که موضوعش دقیقاً چیزی است که --check انتظار دارد.

        `commit-tree` بدونِ لمسِ HEAD یا working tree کار می‌کند، پس
        فیکسچر هیچ اثری روی وضعیتِ کلون نمی‌گذارد.
        """
        import hashlib
        import subprocess
        ver = _read(self.clone, "publish", "VERSION").strip()
        with open(os.path.join(self.clone, "wg_panel.py"), "rb") as fh:
            sha12 = hashlib.sha256(fh.read()).hexdigest()[:12]
        tree = self._git("rev-parse", "HEAD^{tree}")
        r = subprocess.run(
            ["git", "-C", self.clone, "commit-tree", tree,
             "-m", "wg-panel %s+%s" % (ver, sha12)],
            capture_output=True, text=True,
            env=dict(os.environ,
                     GIT_AUTHOR_NAME="test", GIT_AUTHOR_EMAIL="t@example.invalid",
                     GIT_COMMITTER_NAME="test", GIT_COMMITTER_EMAIL="t@example.invalid"))
        self.assertEqual(r.returncode, 0, "ساختِ کامیتِ public شکست: %s" % r.stderr)
        return r.stdout.strip()

    def _commit(self, msg):
        import subprocess
        subprocess.run(["git", "-C", self.clone,
                        "-c", "user.name=test", "-c", "user.email=t@example.invalid",
                        "commit", "-aqm", msg], capture_output=True, check=True)

    def _run(self, *args, timeout=600):
        import subprocess
        e = dict(os.environ)
        # گیت این‌ها را هنگامِ اجرا از داخلِ هوک ست می‌کند و یک بار
        # worktree add را شکستند — صریحاً پاک، چون تست‌رانر هم می‌تواند
        # حاملشان باشد.
        for k in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE",
                  "GIT_OBJECT_DIRECTORY"):
            e.pop(k, None)
        e[self.NESTED] = "1"
        return subprocess.run(
            ["bash", os.path.join(self.clone, "publish/make-public.sh")]
            + list(args),
            cwd=self.clone, capture_output=True, text=True, env=e,
            timeout=timeout)

    def test_a_planted_leak_is_reported_without_a_contradictory_green_line(self):
        """نشتِ کاشته‌شده باید گزارش شود — و خطِ سبز نباید کنارش بیاید.

        این دقیقاً باگِ پلنِ ۰۱۲ است. با کاشتنِ عنصری **جز آخرینِ فهرست**
        (`publish`) بازتولید می‌شود؛ با خودِ publish نمی‌شود، و به همین
        دلیل پنهان ماند.

        🪤 نشت را نمی‌شود با `CLAUDE.md` ِ ساده کاشت: گاردِ **متنیِ**
        خودِ سوئیت (`test_filelist_excludes_the_operational_layer`) در
        اجرای پیش‌پروازِ اسکریپت جلویش را می‌گیرد. ولی آن گارد فقط
        **اولین جزءِ مسیر** را می‌سنجد، پس `./CLAUDE.md` از کنارش رد
        می‌شود و در درخت به همان ریشه می‌نشیند — که خودش نشان می‌دهد
        چرا گاردِ متنی کافی نیست.
        """
        fl = os.path.join(self.clone, "publish/filelist.txt")
        with open(fl, "a", encoding="utf-8") as fh:
            fh.write("\n./CLAUDE.md\n")
        self._commit("planted leak for test")
        head_before = self._git("rev-parse", "HEAD")
        branches_before = self._git("branch", "-a")

        r = self._run("--dry-run")
        out = r.stdout + r.stderr
        self.assertIn("نشت کرد", out, "نشتِ کاشته‌شده گزارش نشد")
        self.assertNotIn("هیچ پوشه/سندِ عملیاتی‌ای وارد نشد", out,
                         "خطِ سبز کنارِ گزارشِ نشت چاپ شد")
        self.assertNotEqual(r.returncode, 0, "با وجودِ نشت موفق خارج شد")
        # و اجرای شکست‌خورده نباید چیزی در مخزن جا بگذارد
        self.assertEqual(self._git("rev-parse", "HEAD"), head_before,
                         "اجرای شکست‌خورده کامیت ساخت")
        self.assertEqual(self._git("branch", "-a"), branches_before,
                         "اجرای شکست‌خورده شاخه ساخت یا حذف کرد")

    def test_check_mode_detects_staleness(self):
        """`--check` باید کهنگی را ببیند.

        بی‌صدا ماندنش دقیقاً همان چیزی است که مالک خواست قرمز شود:
        «اگر یادت برود، public عقب می‌ماند بدونِ اینکه چیزی قرمز شود».
        اگر روزی این کلاس لازم شد کوچک شود، این تست آخرین چیزی است که
        می‌رود.
        """
        self.assertEqual(self._run("--check").returncode, 0,
                         "کلونِ تازه باید هم‌گام باشد")
        with open(os.path.join(self.clone, "wg_panel.py"), "a",
                  encoding="utf-8") as fh:
            fh.write("\n# تغییرِ ساختگیِ تست\n")
        self._commit("source drift for test")
        r = self._run("--check")
        self.assertNotEqual(r.returncode, 0, "--check کهنگی را ندید")
        self.assertIn("عقب است", r.stdout + r.stderr,
                      "پیامِ کهنگی چاپ نشد")

    def test_the_real_repository_is_never_touched(self):
        """قیدِ پیش‌نیازِ همه‌چیزِ این کلاس: مخزنِ واقعی دست‌نخورده بماند.

        اگر این بشکند، هیچ‌کدام از نتایجِ دیگر قابلِ اعتماد نیست.
        """
        import subprocess
        before = subprocess.run(["git", "-C", REPO, "status", "--porcelain"],
                                capture_output=True, text=True).stdout
        self._run("--check")
        after = subprocess.run(["git", "-C", REPO, "status", "--porcelain"],
                               capture_output=True, text=True).stdout
        self.assertEqual(before, after, "مخزنِ واقعی تغییر کرد")


class PublicMetaFileTests(unittest.TestCase):
    """SECURITY / CONTRIBUTING / ورک‌فلوی CI (پلنِ ۰۵۴).

    این سه چیزی‌اند که یک بازدیدکننده بعد از README دنبالشان می‌گردد. اینجا
    فقط وجودشان سنجیده نمی‌شود؛ سنجیده می‌شود که **واقعاً به درختِ عمومی
    برسند** و چیزی وعده ندهند که آنجا نیست.
    """

    @classmethod
    def setUpClass(cls):
        if not os.path.isdir(PUB):
            raise unittest.SkipTest("publish/ در این درخت نیست")

    def test_meta_files_are_whitelisted_and_present(self):
        keep, _drop = _entries(_read(PUB, "filelist.txt"))
        for f in ("CONTRIBUTING.md", "SECURITY.md"):
            with self.subTest(f=f):
                self.assertIn(f, keep, "%s در فهرستِ سفید نیست" % f)
                self.assertTrue(os.path.exists(os.path.join(REPO, f)),
                                "%s وجود ندارد" % f)

    def test_ci_workflow_does_not_reference_unpublished_paths(self):
        """ورک‌فلو نباید مسیری را صدا بزند که در درختِ عمومی نیست.

        `.claude/` عمداً منتشر نمی‌شود، پس ورک‌فلویی که باتری را از آنجا
        صدا بزند روی شاخه‌ی عمومی از **روزِ اول** قرمز است — و یک CI ِ
        همیشه‌قرمز بدتر از نبودنِ CI است، چون کسی دیگر نگاهش نمی‌کند.
        """
        wf = os.path.join(REPO, ".github", "workflows")
        if not os.path.isdir(wf):
            self.skipTest("ورک‌فلو ساخته نشده")
        keep, _drop = _entries(_read(PUB, "filelist.txt"))
        for name in sorted(os.listdir(wf)):
            if not name.endswith((".yml", ".yaml")):
                continue
            body = "\n".join(l for l in _read(wf, name).splitlines()
                             if not l.lstrip().startswith("#"))
            with self.subTest(f=name):
                self.assertNotIn(".claude/", body,
                                 "ورک‌فلو مسیرِ منتشرنشده را صدا می‌زند")
                # هر مسیرِ نسبیِ ./x یا x/ که صدا زده می‌شود باید منتشر شود
                for m in re.finditer(r'\b(tests|docker|deploy|publish|ansible|'
                                     r'online|airgap|scripts)/', body):
                    d = m.group(0)
                    self.assertTrue(
                        any(k == d or k.rstrip("/") == d.rstrip("/")
                            or k.startswith(d) for k in keep),
                        "ورک‌فلو %s را می‌خواهد ولی منتشر نمی‌شود" % d)

    def test_the_workflow_says_it_is_inert(self):
        """بدونِ این جمله، خواننده فرض می‌کند CI دارد اجرا می‌شود.

        مخزن طبقِ قاعده‌ی ثابت هیچ ریموتی ندارد، پس هیچ رانری این را
        برنمی‌دارد. تیکِ سبزی که وجود ندارد بدتر از نبودِ تیک است.
        """
        wf = os.path.join(REPO, ".github", "workflows")
        if not os.path.isdir(wf):
            self.skipTest("ورک‌فلو ساخته نشده")
        for name in sorted(os.listdir(wf)):
            if not name.endswith((".yml", ".yaml")):
                continue
            head = "\n".join(_read(wf, name).splitlines()[:12])
            with self.subTest(f=name):
                self.assertTrue(
                    "اجرا نمی‌شود" in head or "inert" in head.lower(),
                    "ورک‌فلو نمی‌گوید که امروز اجرا نمی‌شود")

    def test_security_md_has_no_placeholder_contact(self):
        """آدرسِ جای‌نگه‌دار از نبودِ فایل بدتر است.

        گزارش‌دهنده‌ی آسیب‌پذیری می‌نویسد و کسی نمی‌خواند — و چون خودش
        فکر می‌کند گزارش داده، سراغِ افشای عمومی هم نمی‌رود.
        """
        p = os.path.join(REPO, "SECURITY.md")
        if not os.path.exists(p):
            self.skipTest("SECURITY.md ساخته نشده — تصمیمِ مالک")
        body = _read(p)
        for bad in ("example.com", "TODO", "FIXME", "your-email",
                    "<address>", "xxx@"):
            self.assertNotIn(bad, body, "آدرسِ جای‌نگه‌دار: %s" % bad)
        self.assertRegex(body, r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
                         "SECURITY.md هیچ آدرسِ تماسی ندارد")

    def test_contributing_does_not_promise_unpublished_tooling(self):
        """CONTRIBUTING نباید دستوری بدهد که در درختِ عمومی اجرا نمی‌شود.

        همان تله‌ی ورک‌فلو، یک فایل آن‌طرف‌تر: باتری در `.claude/` است و
        منتشر نمی‌شود، پس «برای تأیید این را بزن» به خواننده‌ی عمومی یک
        دستورِ همیشه‌شکست می‌دهد. اشاره به‌عنوانِ «ابزارِ نگهدارنده» مجاز
        است؛ **دستور دادنش** نه.
        """
        body = _read(REPO, "CONTRIBUTING.md")
        for m in re.finditer(r"^\s*(?:\$\s*)?(bash|sh)\s+(\S+)", body, re.M):
            path = m.group(2)
            with self.subTest(cmd=path):
                self.assertFalse(
                    path.startswith(".claude/"),
                    "CONTRIBUTING دستورِ اجرای مسیرِ منتشرنشده می‌دهد: %s"
                    % path)


if __name__ == "__main__":
    unittest.main()
