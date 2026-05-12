"""
check.py — Legion VPN subscription builder
Проверяет конфиги по TCP, определяет страну через несколько API,
генерирует JSON-массив и Clash Meta конфиг.
"""

import asyncio
import json
import shutil
import socket
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

import httpx
import yaml

# ─── Пути ────────────────────────────────────────────────────────────────────

INPUT_FILE  = "configs/all_vless.txt"
OUTPUT_JSON = "runvpn.json"
OUTPUT_YAML = "legion_clash.yaml"
OUTPUT_LOG  = "check_log.txt"

# ─── Бренд ───────────────────────────────────────────────────────────────────

BRAND             = "Ascome"
ICON_UNKNOWN      = "🇸🇴"
BRAND_AUTO        = f"{ICON_UNKNOWN} {BRAND} · Авто"
BRAND_AUTO_PREFIX = f"{BRAND} · Авто · "
BRAND_PREFIX      = f"{BRAND} · "

# ─── Гео ─────────────────────────────────────────────────────────────────────

COUNTRY_FLAGS: dict[str, str] = {
    "US": "🇺🇸", "DE": "🇩🇪", "NL": "🇳🇱", "FR": "🇫🇷",
    "GB": "🇬🇧", "FI": "🇫🇮", "SE": "🇸🇪", "CH": "🇨🇭",
    "AT": "🇦🇹", "JP": "🇯🇵", "SG": "🇸🇬", "HK": "🇭🇰",
    "PL": "🇵🇱", "CZ": "🇨🇿", "UA": "🇺🇦", "TR": "🇹🇷",
    "RU": "🇷🇺", "KZ": "🇰🇿", "AE": "🇦🇪", "LT": "🇱🇹",
    "LV": "🇱🇻", "EE": "🇪🇪", "BG": "🇧🇬", "RO": "🇷🇴",
    "CA": "🇨🇦", "AU": "🇦🇺", "BR": "🇧🇷", "IN": "🇮🇳",
    "IT": "🇮🇹", "ES": "🇪🇸", "PT": "🇵🇹", "NO": "🇳🇴",
    "DK": "🇩🇰", "BE": "🇧🇪", "HU": "🇭🇺", "GR": "🇬🇷",
    "SK": "🇸🇰", "HR": "🇭🇷", "RS": "🇷🇸", "MD": "🇲🇩",
    "GE": "🇬🇪", "AM": "🇦🇲", "AZ": "🇦🇿", "UZ": "🇺🇿",
    "KR": "🇰🇷", "TW": "🇹🇼", "TH": "🇹🇭", "MY": "🇲🇾",
    "ID": "🇮🇩", "VN": "🇻🇳", "IL": "🇮🇱", "ZA": "🇿🇦",
    "MX": "🇲🇽", "AR": "🇦🇷", "CL": "🇨🇱", "CO": "🇨🇴",
    "IS": "🇮🇸", "LU": "🇱🇺", "CY": "🇨🇾", "MT": "🇲🇹",
}

COUNTRY_NAMES_RU: dict[str, str] = {
    "US": "США",           "DE": "Германия",      "NL": "Нидерланды",    "FR": "Франция",
    "GB": "Великобритания","FI": "Финляндия",     "SE": "Швеция",        "CH": "Швейцария",
    "AT": "Австрия",       "JP": "Япония",         "SG": "Сингапур",      "HK": "Гонконг",
    "PL": "Польша",        "CZ": "Чехия",          "UA": "Украина",       "TR": "Турция",
    "RU": "Россия",        "KZ": "Казахстан",      "AE": "ОАЭ",           "LT": "Литва",
    "LV": "Латвия",        "EE": "Эстония",        "BG": "Болгария",      "RO": "Румыния",
    "CA": "Канада",        "AU": "Австралия",       "BR": "Бразилия",      "IN": "Индия",
    "IT": "Италия",        "ES": "Испания",         "PT": "Португалия",    "NO": "Норвегия",
    "DK": "Дания",         "BE": "Бельгия",         "HU": "Венгрия",       "GR": "Греция",
    "SK": "Словакия",      "HR": "Хорватия",        "RS": "Сербия",        "MD": "Молдова",
    "GE": "Грузия",        "AM": "Армения",         "AZ": "Азербайджан",   "UZ": "Узбекистан",
    "KR": "Корея",         "TW": "Тайвань",         "TH": "Таиланд",       "MY": "Малайзия",
    "ID": "Индонезия",     "VN": "Вьетнам",         "IL": "Израиль",       "ZA": "ЮАР",
    "MX": "Мексика",       "AR": "Аргентина",       "CL": "Чили",          "CO": "Колумбия",
    "IS": "Исландия",      "LU": "Люксембург",      "CY": "Кипр",          "MT": "Мальта",
}

COUNTRY_NAMES_EN: dict[str, str] = {
    "US": "United States", "DE": "Germany",      "NL": "Netherlands",   "FR": "France",
    "GB": "United Kingdom","FI": "Finland",      "SE": "Sweden",        "CH": "Switzerland",
    "AT": "Austria",       "JP": "Japan",        "SG": "Singapore",     "HK": "Hong Kong",
    "PL": "Poland",        "CZ": "Czechia",      "UA": "Ukraine",       "TR": "Turkey",
    "RU": "Russia",        "KZ": "Kazakhstan",   "AE": "UAE",           "LT": "Lithuania",
    "LV": "Latvia",        "EE": "Estonia",      "BG": "Bulgaria",      "RO": "Romania",
    "CA": "Canada",        "AU": "Australia",    "BR": "Brazil",        "IN": "India",
    "IT": "Italy",         "ES": "Spain",        "PT": "Portugal",      "NO": "Norway",
    "DK": "Denmark",       "BE": "Belgium",      "HU": "Hungary",       "GR": "Greece",
    "SK": "Slovakia",      "HR": "Croatia",      "RS": "Serbia",        "MD": "Moldova",
    "GE": "Georgia",       "AM": "Armenia",      "AZ": "Azerbaijan",    "UZ": "Uzbekistan",
    "KR": "South Korea",   "TW": "Taiwan",       "TH": "Thailand",      "MY": "Malaysia",
    "ID": "Indonesia",     "VN": "Vietnam",      "IL": "Israel",        "ZA": "South Africa",
    "MX": "Mexico",        "AR": "Argentina",    "CL": "Chile",         "CO": "Colombia",
    "IS": "Iceland",       "LU": "Luxembourg",   "CY": "Cyprus",        "MT": "Malta",
}

GEO_APIS: list[tuple] = [
    (
        lambda ip: f"https://ipwho.is/{ip}",
        lambda d: d.get("country_code"),
    ),
    (
        lambda ip: f"https://ipapi.co/{ip}/json/",
        lambda d: d.get("country_code"),
    ),
    (
        lambda ip: f"https://freeipapi.com/api/json/{ip}",
        lambda d: d.get("countryCode"),
    ),
    (
        lambda ip: f"https://ip-api.com/json/{ip}?fields=countryCode",
        lambda d: d.get("countryCode"),
    ),
    (
        lambda ip: f"https://ipinfo.io/{ip}/json",
        lambda d: d.get("country"),
    ),
    (
        lambda ip: f"https://api.iplocation.net/?ip={ip}",
        lambda d: d.get("country_code2"),
    ),
    (
        lambda ip: f"https://ip.guide/{ip}",
        lambda d: (
            (d.get("location") or {}).get("country_code")
            or (d.get("network") or {}).get("country_code")
        ),
    ),
    (
        lambda ip: f"https://extreme-ip-lookup.com/json/{ip}?key=free",
        lambda d: d.get("countryCode"),
    ),
    (
        lambda ip: f"https://ipapi.is/json/?ip={ip}",
        lambda d: (d.get("location") or {}).get("country_code"),
    ),
    (
        lambda ip: f"https://api.ipbase.com/v1/json/?ip={ip}",
        lambda d: d.get("country_code"),
    ),
]

# Geo APIs for through-proxy check (caller's IP based, simpler URLs)
# These are queried THROUGH the proxy to determine exit country
PROXY_GEO_APIS: list[tuple] = [
    ("http://ip-api.com/json?fields=countryCode", lambda d: d.get("countryCode")),
    ("https://ipwho.is/", lambda d: d.get("country_code")),
    ("http://ipinfo.io/json", lambda d: d.get("country")),
    ("http://freeipapi.com/api/json", lambda d: d.get("countryCode")),
]

# ─── Датакласс результата ─────────────────────────────────────────────────────

@dataclass
class CheckResult:
    tag:          str
    name:         str
    host:         str
    port:         int
    tcp_ms:       float | None
    country:      str
    flag:         str
    exit_country: str
    exit_flag:    str
    alive:        bool


# ══════════════════════════════════════════════════════════════════════════════
#  А Д Б Л О К  —  расширенные списки
# ══════════════════════════════════════════════════════════════════════════════

# ── YouTube-специфичная реклама ───────────────────────────────────────────────
# Блокируем только инфраструктуру доставки рекламы, НЕ сам YouTube
YOUTUBE_AD_DOMAINS: list[str] = [
    # IMA SDK — главный механизм показа рекламы в YouTube
    "domain:imasdk.googleapis.com",
    "domain:ad.youtube.com",
    "domain:ads.youtube.com",
    # Сервер монетизации
    "domain:youtubei.googleapis.com",          # частичная — только /ads endpoint
    # Трекинг просмотра рекламы
    "domain:www.youtube.com/api/stats/ads",
    "domain:www.youtube.com/pagead",
    "domain:www.youtube.com/ptracking",
    "domain:www.youtube.com/youtubei/v1/log_event",
    # DoubleClick внутри YouTube
    "domain:doubleclick.net",
    "domain:ad.doubleclick.net",
    "domain:stats.g.doubleclick.net",
    "domain:securepubads.g.doubleclick.net",
    # Consent / GDPR overlay
    "domain:fundingchoicesmessages.google.com",
    "domain:fundingchoices.google.com",
    # Google Ads общие
    "domain:adservice.google.com",
    "domain:googleadservices.com",
    "domain:pagead2.googlesyndication.com",
    "domain:tpc.googlesyndication.com",
    "domain:partner.googleadservices.com",
    "domain:adsensecustomsearchads.com",
]

# ── Российские рекламные и трекинг-домены ─────────────────────────────────────
RU_AD_DOMAINS: list[str] = [
    # Яндекс реклама
    "domain:an.yandex.ru",
    "domain:bs.yandex.ru",
    "domain:mc.yandex.ru",
    "domain:webvisor.com",
    "domain:metrika.yandex.ru",
    "domain:metrika.yandex.com",
    "domain:yandex-team.ru",           # внутренняя аналитика
    "domain:counter.yadro.ru",
    "domain:top.mail.ru",
    "domain:top-fwz1.mail.ru",
    "domain:rs.mail.ru",               # Mail.ru трекер
    "domain:imgsmail.ru",              # рекламные баннеры Mail.ru
    # Adfox
    "domain:banners.adfox.ru",
    "domain:ads.adfox.ru",
    "domain:adfox.ru",
    "domain:adfox.me",
    # Sape, Begun, Nolix
    "domain:sape.ru",
    "domain:begun.ru",
    "domain:nolix.ru",
    "domain:adspirit.de",
    # Soloway
    "domain:soloway.ru",
    # Rbk.money / РБК реклама
    "domain:ads.rbc.ru",
    "domain:banners.rbc.ru",
    # Teasernet
    "domain:teasernet.com",
    "domain:gnezdo.ru",
    # Advertur
    "domain:advertur.ru",
    # Rambler реклама
    "domain:ad.rambler.ru",
    "domain:tns-counter.ru",
    "domain:rambler-co.ru",
    # TargetMail / DMP
    "domain:targetmail.ru",
    "domain:dmp.one",
    # Hybrid (российская programmatic)
    "domain:hybrid.ai",
    "domain:hyb.ru",
    # ОК / Одноклассники реклама
    "domain:ads.ok.ru",
    "domain:static.ok.ru",
    # ВКонтакте реклама
    "domain:ads.vk.com",
    "domain:vk-apps.com",              # tracking
    # Спонсорский контент / Яндекс
    "domain:yabs.yandex.ru",
    "domain:awaps.yandex.net",
    "domain:awaps.yandex.ru",
    "domain:storage.mds.yandex.net",   # рекламные креативы
    # Mindbox / RetailRocket
    "domain:mindbox.ru",
    "domain:retailrocket.ru",
    "domain:retailrocket.net",
    # Carrot quest / Jivosite чаты-всплывашки (опционально)
    "domain:carrotquest.io",
    # Calltouch
    "domain:calltouch.ru",
    # CoMagic
    "domain:comagic.ru",
    # Roistat
    "domain:roistat.com",
    # Mango Office
    "domain:mango-office.ru",
    # Albato / Bitrix трекеры
    "domain:albato.ru",
    # Click.ru
    "domain:click.ru",
    # Kadam
    "domain:kadam.net",
    # AdSmart
    "domain:adsmart.ru",
    # GetIntent
    "domain:getintent.com",
    # Segmento
    "domain:segmento.ru",
    # MyTarget (Mail.ru Group)
    "domain:target.my.com",
    "domain:targetix.net",
    "domain:mradx.net",
    "domain:mx5.mail.ru",
    # Relap
    "domain:relap.io",
    # eSputnik
    "domain:esputnik.com",
    # Criteo RU
    "domain:dis.eu.criteo.com",
    "domain:criteo.com",
    # Sociomantic / Dunnhumby
    "domain:sociomantic.com",
    # Weborama
    "domain:weborama.ru",
    "domain:weborama.com",
    # Gemius
    "domain:gemius.pl",
    "domain:hit.gemius.pl",
    # Hotlog
    "domain:hotlog.ru",
    # Liveinternet счётчик
    "domain:counter.rambler.ru",
    "domain:tns-counter.ru",
    "domain:hit.ua",
    "domain:bigmir.net",
]

# ── Телеметрия ОС и приложений ────────────────────────────────────────────────
TELEMETRY_DOMAINS: list[str] = [
    # Windows телеметрия
    "domain:telemetry.microsoft.com",
    "domain:vortex.data.microsoft.com",
    "domain:vortex-win.data.microsoft.com",
    "domain:telecommand.telemetry.microsoft.com",
    "domain:oca.telemetry.microsoft.com",
    "domain:sqm.telemetry.microsoft.com",
    "domain:watson.telemetry.microsoft.com",
    "domain:redir.metaservices.microsoft.com",
    "domain:choice.microsoft.com",
    "domain:df.telemetry.microsoft.com",
    "domain:reports.wes.df.telemetry.microsoft.com",
    "domain:wes.df.telemetry.microsoft.com",
    "domain:services.wes.df.telemetry.microsoft.com",
    "domain:sqm.df.telemetry.microsoft.com",
    "domain:statsfe2.ws.microsoft.com",
    "domain:corpext.msitadfs.glbdns2.microsoft.com",
    "domain:compatexchange.cloudapp.net",
    "domain:cs1.wpc.v0cdn.net",
    "domain:a-0001.a-msedge.net",
    "domain:statsfe2.update.microsoft.com.akadns.net",
    "domain:sls.update.microsoft.com.akadns.net",
    "domain:fe2.update.microsoft.com.akadns.net",
    "domain:diagnostics.support.microsoft.com",
    "domain:watson.ppe.telemetry.microsoft.com",
    "domain:settings-win.data.microsoft.com",
    "domain:v10.events.data.microsoft.com",
    "domain:v10.vortex-win.data.microsoft.com",
    "domain:v20.events.data.microsoft.com",
    # Apple телеметрия
    "domain:metrics.apple.com",
    "domain:xp.apple.com",
    "domain:radarsubmissions.apple.com",
    # Google телеметрия
    "domain:app-measurement.com",
    "domain:firebaselogging-pa.googleapis.com",
    "domain:crashlytics.com",
    "domain:settings.crashlytics.com",
    # Samsung
    "domain:samsungqbe.com",
    "domain:analyticsv2.samsungcloud.com",
    "domain:log-config.samsungcloud.com",
    # Android / AOSP
    "domain:android.clients.google.com",   # только для телеметрии, GMS оставить
    "domain:connectivitycheck.gstatic.com",
    # Xiaomi / MIUI
    "domain:data.mistat.xiaomi.com",
    "domain:api.ad.xiaomi.com",
    "domain:sdkconfig.ad.xiaomi.com",
    "domain:globalapi.ad.xiaomi.com",
    "domain:globalapi.ad.intl.xiaomi.com",
    "domain:tracking.miui.com",
    "domain:dig.miui.com",
    # Huawei
    "domain:logservice.hicloud.com",
    "domain:logservice1.hicloud.com",
    "domain:metrics2.data.hicloud.com",
    "domain:metrics3.data.hicloud.com",
    # Amazon телеметрия
    "domain:device-metrics-us.amazon.com",
    "domain:device-metrics-us-2.amazon.com",
    "domain:firs.amazon.com",
]

# ── Malware / Phishing / Scam ─────────────────────────────────────────────────
# ── Malware / Phishing / Scam ─────────────────────────────────────────────────
# Убраны geosite:malware, geosite:phishing, geosite:cryptominers —
# их нет в стандартной базе v2fly/domain-list-community.
# Реальные категории которые точно есть:
MALWARE_DOMAINS: list[str] = [
    "geosite:category-porn",        # опционально
]

# ── Расширенный список рекламы (глобальный) ───────────────────────────────────
ADBLOCK_DNS_DOMAINS: list[str] = [
    "geosite:category-ads",
]

ADBLOCK_ROUTING_DOMAINS: list[str] = [
    # ── GeoSite категории ──────────────────────────────────────────────────
    "geosite:category-ads-all",
    "geosite:category-ads",

    # ── YouTube реклама ────────────────────────────────────────────────────
    *YOUTUBE_AD_DOMAINS,

    # ── Российская реклама ─────────────────────────────────────────────────
    *RU_AD_DOMAINS,

    # ── Телеметрия ─────────────────────────────────────────────────────────
    *TELEMETRY_DOMAINS,

    # ── Malware / Phishing ─────────────────────────────────────────────────
    *MALWARE_DOMAINS,

    # ── Google Ads / DoubleClick ───────────────────────────────────────────
    "domain:ads.google.com",
    "domain:adservice.google.com",
    "domain:googleadservices.com",
    "domain:googlesyndication.com",
    "domain:googletagmanager.com",
    "domain:googletagservices.com",
    "domain:g.doubleclick.net",
    "domain:pagead2.googlesyndication.com",
    "domain:adwords.google.com",

    # ── Facebook / Meta Ads ────────────────────────────────────────────────
    "domain:an.facebook.com",
    "domain:connect.facebook.net",

    # ── TikTok / ByteDance Ads ────────────────────────────────────────────
    "domain:ads.tiktok.com",
    "domain:analytics.tiktok.com",
    "domain:log.tiktok.com",
    "domain:mon.tiktok.com",

    # ── Twitter / X Ads ───────────────────────────────────────────────────
    "domain:ads-twitter.com",
    "domain:ads.twitter.com",

    # ── Amazon Ads ────────────────────────────────────────────────────────
    "domain:amazon-adsystem.com",
    "domain:aax.amazon-adsystem.com",
    "domain:fls-na.amazon.com",

    # ── Mobile Ad Networks ────────────────────────────────────────────────
    "domain:adcolony.com",
    "domain:applovin.com",
    "domain:vungle.com",
    "domain:unityads.unity3d.com",
    "domain:ads.unityads.unity3d.com",
    "domain:config.unityads.unity3d.com",
    "domain:publisher-event.unityads.unity3d.com",
    "domain:auction.unityads.unity3d.com",
    "domain:pangle.io",
    "domain:pangleglobal.com",
    "domain:inmobi.com",
    "domain:mopub.com",
    "domain:smaato.net",
    "domain:mobvista.com",
    "domain:mintegral.com",
    "domain:ogury.com",
    "domain:tapjoy.com",
    "domain:chartboost.com",
    "domain:ironsrc.com",
    "domain:ironsource.com",
    "domain:supersonic.com",
    "domain:fyber.com",
    "domain:inner-active.mobi",
    "domain:widespace.com",
    "domain:loopme.com",
    "domain:startapp.com",
    "domain:kidoz.net",

    # ── Analytics / Trackers ──────────────────────────────────────────────
    "domain:analytics.google.com",
    "domain:www.google-analytics.com",
    "domain:ssl.google-analytics.com",
    "domain:google-analytics.com",
    "domain:mparticle.com",
    "domain:adjust.com",
    "domain:app.adjust.com",
    "domain:appadj.st",
    "domain:branch.io",
    "domain:app.link",
    "domain:mixpanel.com",
    "domain:api.mixpanel.com",
    "domain:amplitude.com",
    "domain:api.amplitude.com",
    "domain:segment.com",
    "domain:api.segment.io",
    "domain:cdn.segment.com",
    "domain:heap.io",
    "domain:heapanalytics.com",
    "domain:hotjar.com",
    "domain:static.hotjar.com",
    "domain:insights.hotjar.com",
    "domain:fullstory.com",
    "domain:rs.fullstory.com",
    "domain:logrocket.com",
    "domain:newrelic.com",
    "domain:bam.nr-data.net",
    "domain:appsflyer.com",
    "domain:deep.link",
    "domain:singular.net",
    "domain:kochava.com",
    "domain:control.kochava.com",
    "domain:flurry.com",
    "domain:data.flurry.com",

    # ── Criteo / Retargeting ──────────────────────────────────────────────
    "domain:widget.criteo.com",
    "domain:static.criteo.net",
    "domain:dis.us.criteo.com",

    # ── Outbrain / Taboola / Native Ads ──────────────────────────────────
    "domain:outbrain.com",
    "domain:widgets.outbrain.com",
    "domain:taboola.com",
    "domain:trc.taboola.com",
    "domain:nr-data.taboola.com",
    "domain:zemanta.com",

    # ── Programmatic / RTB ────────────────────────────────────────────────
    "domain:rubiconproject.com",
    "domain:fastlane.rubiconproject.com",
    "domain:pubmatic.com",
    "domain:ads.pubmatic.com",
    "domain:openx.com",
    "domain:delivery.openx.com",
    "domain:appnexus.com",
    "domain:ib.adnxs.com",
    "domain:adnxs.com",
    "domain:smartadserver.com",
    "domain:triplelift.com",
    "domain:tlx.3lift.com",
    "domain:indexexchange.com",
    "domain:casalemedia.com",
    "domain:33across.com",
    "domain:sic.33across.com",
    "domain:sharethrough.com",
    "domain:turn.com",
    "domain:media.net",
    "domain:contextweb.com",
    "domain:pulsepoint.com",
    "domain:advertising.com",
    "domain:adtech.com",
    "domain:yieldmo.com",
    "domain:sonobi.com",
    "domain:sovrn.com",
    "domain:lijit.com",
    "domain:districtm.io",
    "domain:bidswitch.net",
    "domain:e.bidswitch.net",
    "domain:adform.net",
    "domain:track.adform.net",
    "domain:xandr.com",
    "domain:adsrvr.org",
    "domain:thetradedesk.com",
    "domain:id5-sync.com",
    "domain:liveintent.com",
    "domain:liveramp.com",
    "domain:ats.rlcdn.com",
    "domain:id.rlcdn.com",
    "domain:quantserve.com",
    "domain:pixel.quantserve.com",
    "domain:scorecardresearch.com",
    "domain:b.scorecardresearch.com",

    # ── Spy / Fingerprinting ──────────────────────────────────────────────
    "domain:fingerprintjs.com",
    "domain:fp.fingerprintjs.com",
    "domain:cdn.fingerprintjs.com",
    "domain:visitorqueue.com",
    "domain:ipqualityscore.com",
    "domain:deviceatlas.com",
    "domain:iovation.com",
    "domain:threatmetrix.com",
    "domain:h.clarity.ms",
    "domain:clarity.ms",
    "domain:bat.bing.com",
    "domain:ads.microsoft.com",
    "domain:c.msn.com",

    # ── Push-уведомления рекламные ────────────────────────────────────────
    "domain:onesignal.com",
    "domain:cdn.onesignal.com",
    "domain:pushwoosh.com",
    "domain:cp.pushwoosh.com",
    "domain:airship.com",
    "domain:go.urbanairship.com",
    "domain:device-api.urbanairship.com",
    "domain:pushpad.eu",

    # ── Spy-пиксели ───────────────────────────────────────────────────────
    "domain:px.ads.linkedin.com",
    "domain:snap.licdn.com",
    "domain:ct.pinterest.com",
    "domain:trk.pinterest.com",
    "domain:ads.pinterest.com",

    # ── Разное ────────────────────────────────────────────────────────────
    "domain:adskeeper.com",
    "domain:adgrx.com",
    "domain:ad.doubleclick.net",
    "domain:securepubads.g.doubleclick.net",
    "domain:tpc.googlesyndication.com",
    "domain:partner.googleadservices.com",
    "domain:cse.google.com",
    "domain:imasdk.googleapis.com",
]

# IP-подсети рекламных CDN
ADBLOCK_ROUTING_IPS: list[str] = [
    # DoubleClick / Google Ads
    "74.125.0.0/16",
    "209.85.128.0/17",
    # Criteo
    "178.250.0.0/21",
    # AppNexus / Xandr
    "68.67.128.0/21",
    "185.20.8.0/22",
    # Taboola
    "87.248.100.0/21",
    # Yandex Ads
    "213.180.193.0/24",
    "77.88.21.0/24",
    # Mail.ru Ads
    "94.100.180.0/22",
    # Smaato
    "66.235.200.0/21",
]

# Правило блокировки для Xray routing
ADBLOCK_RULE: dict = {
    "type":        "field",
    "outboundTag": "block",
    "domain":      ADBLOCK_ROUTING_DOMAINS,
    "ip":          ADBLOCK_ROUTING_IPS,
}

# ── Правила для Clash ─────────────────────────────────────────────────────────

CLASH_ADBLOCK_RULES: list[str] = [
    # GeoSite
    "GEOSITE,category-ads-all,REJECT",
    "GEOSITE,category-ads,REJECT",
    "GEOSITE,malware,REJECT",
    "GEOSITE,phishing,REJECT",
    "GEOSITE,cryptominers,REJECT",

    # ── YouTube реклама ────────────────────────────────────────────────────
    "DOMAIN-SUFFIX,imasdk.googleapis.com,REJECT",
    "DOMAIN-SUFFIX,ad.youtube.com,REJECT",
    "DOMAIN-SUFFIX,ads.youtube.com,REJECT",
    "DOMAIN-SUFFIX,fundingchoicesmessages.google.com,REJECT",
    "DOMAIN-SUFFIX,fundingchoices.google.com,REJECT",
    # Блокировка рекламных запросов YouTube через keyword (Clash поддерживает)
    "DOMAIN-KEYWORD,pagead,REJECT",
    "DOMAIN-KEYWORD,adservice,REJECT",
    "DOMAIN-KEYWORD,doubleclick,REJECT",

    # ── Российская реклама ─────────────────────────────────────────────────
    "DOMAIN-SUFFIX,an.yandex.ru,REJECT",
    "DOMAIN-SUFFIX,bs.yandex.ru,REJECT",
    "DOMAIN-SUFFIX,mc.yandex.ru,REJECT",
    "DOMAIN-SUFFIX,webvisor.com,REJECT",
    "DOMAIN-SUFFIX,metrika.yandex.ru,REJECT",
    "DOMAIN-SUFFIX,metrika.yandex.com,REJECT",
    "DOMAIN-SUFFIX,counter.yadro.ru,REJECT",
    "DOMAIN-SUFFIX,top.mail.ru,REJECT",
    "DOMAIN-SUFFIX,top-fwz1.mail.ru,REJECT",
    "DOMAIN-SUFFIX,rs.mail.ru,REJECT",
    "DOMAIN-SUFFIX,imgsmail.ru,REJECT",
    "DOMAIN-SUFFIX,banners.adfox.ru,REJECT",
    "DOMAIN-SUFFIX,ads.adfox.ru,REJECT",
    "DOMAIN-SUFFIX,adfox.ru,REJECT",
    "DOMAIN-SUFFIX,adfox.me,REJECT",
    "DOMAIN-SUFFIX,sape.ru,REJECT",
    "DOMAIN-SUFFIX,begun.ru,REJECT",
    "DOMAIN-SUFFIX,nolix.ru,REJECT",
    "DOMAIN-SUFFIX,soloway.ru,REJECT",
    "DOMAIN-SUFFIX,ads.rbc.ru,REJECT",
    "DOMAIN-SUFFIX,banners.rbc.ru,REJECT",
    "DOMAIN-SUFFIX,teasernet.com,REJECT",
    "DOMAIN-SUFFIX,gnezdo.ru,REJECT",
    "DOMAIN-SUFFIX,advertur.ru,REJECT",
    "DOMAIN-SUFFIX,ad.rambler.ru,REJECT",
    "DOMAIN-SUFFIX,tns-counter.ru,REJECT",
    "DOMAIN-SUFFIX,targetmail.ru,REJECT",
    "DOMAIN-SUFFIX,dmp.one,REJECT",
    "DOMAIN-SUFFIX,hybrid.ai,REJECT",
    "DOMAIN-SUFFIX,hyb.ru,REJECT",
    "DOMAIN-SUFFIX,ads.ok.ru,REJECT",
    "DOMAIN-SUFFIX,ads.vk.com,REJECT",
    "DOMAIN-SUFFIX,vk-apps.com,REJECT",
    "DOMAIN-SUFFIX,yabs.yandex.ru,REJECT",
    "DOMAIN-SUFFIX,awaps.yandex.net,REJECT",
    "DOMAIN-SUFFIX,awaps.yandex.ru,REJECT",
    "DOMAIN-SUFFIX,mindbox.ru,REJECT",
    "DOMAIN-SUFFIX,retailrocket.ru,REJECT",
    "DOMAIN-SUFFIX,retailrocket.net,REJECT",
    "DOMAIN-SUFFIX,calltouch.ru,REJECT",
    "DOMAIN-SUFFIX,comagic.ru,REJECT",
    "DOMAIN-SUFFIX,roistat.com,REJECT",
    "DOMAIN-SUFFIX,target.my.com,REJECT",
    "DOMAIN-SUFFIX,targetix.net,REJECT",
    "DOMAIN-SUFFIX,mradx.net,REJECT",
    "DOMAIN-SUFFIX,relap.io,REJECT",
    "DOMAIN-SUFFIX,kadam.net,REJECT",
    "DOMAIN-SUFFIX,adsmart.ru,REJECT",
    "DOMAIN-SUFFIX,getintent.com,REJECT",
    "DOMAIN-SUFFIX,segmento.ru,REJECT",
    "DOMAIN-SUFFIX,weborama.ru,REJECT",
    "DOMAIN-SUFFIX,weborama.com,REJECT",
    "DOMAIN-SUFFIX,hotlog.ru,REJECT",
    "DOMAIN-SUFFIX,gemius.pl,REJECT",
    "DOMAIN-SUFFIX,bigmir.net,REJECT",
    "DOMAIN-SUFFIX,hit.ua,REJECT",

    # ── Телеметрия Windows ─────────────────────────────────────────────────
    "DOMAIN-SUFFIX,telemetry.microsoft.com,REJECT",
    "DOMAIN-SUFFIX,vortex.data.microsoft.com,REJECT",
    "DOMAIN-SUFFIX,vortex-win.data.microsoft.com,REJECT",
    "DOMAIN-SUFFIX,settings-win.data.microsoft.com,REJECT",
    "DOMAIN-SUFFIX,v10.events.data.microsoft.com,REJECT",
    "DOMAIN-SUFFIX,v20.events.data.microsoft.com,REJECT",
    "DOMAIN-SUFFIX,watson.telemetry.microsoft.com,REJECT",

    # ── Телеметрия мобильных ───────────────────────────────────────────────
    "DOMAIN-SUFFIX,tracking.miui.com,REJECT",
    "DOMAIN-SUFFIX,dig.miui.com,REJECT",
    "DOMAIN-SUFFIX,api.ad.xiaomi.com,REJECT",
    "DOMAIN-SUFFIX,sdkconfig.ad.xiaomi.com,REJECT",
    "DOMAIN-SUFFIX,globalapi.ad.xiaomi.com,REJECT",
    "DOMAIN-SUFFIX,data.mistat.xiaomi.com,REJECT",
    "DOMAIN-SUFFIX,samsungqbe.com,REJECT",
    "DOMAIN-SUFFIX,analyticsv2.samsungcloud.com,REJECT",
    "DOMAIN-SUFFIX,metrics.apple.com,REJECT",

    # ── Google Ads ─────────────────────────────────────────────────────────
    "DOMAIN-SUFFIX,ads.google.com,REJECT",
    "DOMAIN-SUFFIX,adservice.google.com,REJECT",
    "DOMAIN-SUFFIX,doubleclick.net,REJECT",
    "DOMAIN-SUFFIX,googleadservices.com,REJECT",
    "DOMAIN-SUFFIX,googlesyndication.com,REJECT",
    "DOMAIN-SUFFIX,googletagmanager.com,REJECT",
    "DOMAIN-SUFFIX,googletagservices.com,REJECT",
    "DOMAIN-SUFFIX,pagead2.googlesyndication.com,REJECT",
    "DOMAIN-SUFFIX,google-analytics.com,REJECT",
    "DOMAIN-SUFFIX,app-measurement.com,REJECT",
    "DOMAIN-SUFFIX,crashlytics.com,REJECT",

    # ── Facebook / Meta ────────────────────────────────────────────────────
    "DOMAIN-SUFFIX,an.facebook.com,REJECT",
    "DOMAIN-SUFFIX,connect.facebook.net,REJECT",

    # ── TikTok ────────────────────────────────────────────────────────────
    "DOMAIN-SUFFIX,ads.tiktok.com,REJECT",
    "DOMAIN-SUFFIX,analytics.tiktok.com,REJECT",
    "DOMAIN-SUFFIX,log.tiktok.com,REJECT",
    "DOMAIN-SUFFIX,mon.tiktok.com,REJECT",

    # ── Amazon ────────────────────────────────────────────────────────────
    "DOMAIN-SUFFIX,amazon-adsystem.com,REJECT",
    "DOMAIN-SUFFIX,fls-na.amazon.com,REJECT",
    "DOMAIN-SUFFIX,device-metrics-us.amazon.com,REJECT",

    # ── Mobile SDKs ───────────────────────────────────────────────────────
    "DOMAIN-SUFFIX,adcolony.com,REJECT",
    "DOMAIN-SUFFIX,applovin.com,REJECT",
    "DOMAIN-SUFFIX,vungle.com,REJECT",
    "DOMAIN-SUFFIX,unityads.unity3d.com,REJECT",
    "DOMAIN-SUFFIX,pangle.io,REJECT",
    "DOMAIN-SUFFIX,pangleglobal.com,REJECT",
    "DOMAIN-SUFFIX,inmobi.com,REJECT",
    "DOMAIN-SUFFIX,mintegral.com,REJECT",
    "DOMAIN-SUFFIX,ironsource.com,REJECT",
    "DOMAIN-SUFFIX,chartboost.com,REJECT",
    "DOMAIN-SUFFIX,tapjoy.com,REJECT",
    "DOMAIN-SUFFIX,fyber.com,REJECT",
    "DOMAIN-SUFFIX,startapp.com,REJECT",

    # ── Analytics / Trackers ──────────────────────────────────────────────
    "DOMAIN-SUFFIX,adjust.com,REJECT",
    "DOMAIN-SUFFIX,branch.io,REJECT",
    "DOMAIN-SUFFIX,mixpanel.com,REJECT",
    "DOMAIN-SUFFIX,amplitude.com,REJECT",
    "DOMAIN-SUFFIX,segment.io,REJECT",
    "DOMAIN-SUFFIX,heap.io,REJECT",
    "DOMAIN-SUFFIX,hotjar.com,REJECT",
    "DOMAIN-SUFFIX,fullstory.com,REJECT",
    "DOMAIN-SUFFIX,appsflyer.com,REJECT",
    "DOMAIN-SUFFIX,kochava.com,REJECT",
    "DOMAIN-SUFFIX,flurry.com,REJECT",
    "DOMAIN-SUFFIX,mparticle.com,REJECT",
    "DOMAIN-SUFFIX,singular.net,REJECT",

    # ── Programmatic ──────────────────────────────────────────────────────
    "DOMAIN-SUFFIX,criteo.com,REJECT",
    "DOMAIN-SUFFIX,outbrain.com,REJECT",
    "DOMAIN-SUFFIX,taboola.com,REJECT",
    "DOMAIN-SUFFIX,rubiconproject.com,REJECT",
    "DOMAIN-SUFFIX,pubmatic.com,REJECT",
    "DOMAIN-SUFFIX,openx.com,REJECT",
    "DOMAIN-SUFFIX,adnxs.com,REJECT",
    "DOMAIN-SUFFIX,smartadserver.com,REJECT",
    "DOMAIN-SUFFIX,indexexchange.com,REJECT",
    "DOMAIN-SUFFIX,casalemedia.com,REJECT",
    "DOMAIN-SUFFIX,adsrvr.org,REJECT",
    "DOMAIN-SUFFIX,thetradedesk.com,REJECT",
    "DOMAIN-SUFFIX,quantserve.com,REJECT",
    "DOMAIN-SUFFIX,scorecardresearch.com,REJECT",
    "DOMAIN-SUFFIX,33across.com,REJECT",
    "DOMAIN-SUFFIX,sharethrough.com,REJECT",
    "DOMAIN-SUFFIX,triplelift.com,REJECT",
    "DOMAIN-SUFFIX,bidswitch.net,REJECT",
    "DOMAIN-SUFFIX,adform.net,REJECT",

    # ── Fingerprinting / Spy ──────────────────────────────────────────────
    "DOMAIN-SUFFIX,fingerprintjs.com,REJECT",
    "DOMAIN-SUFFIX,clarity.ms,REJECT",
    "DOMAIN-SUFFIX,bat.bing.com,REJECT",
    "DOMAIN-SUFFIX,ads.microsoft.com,REJECT",

    # ── Push ──────────────────────────────────────────────────────────────
    "DOMAIN-SUFFIX,onesignal.com,REJECT",
    "DOMAIN-SUFFIX,pushwoosh.com,REJECT",

    # ── Пиксели ───────────────────────────────────────────────────────────
    "DOMAIN-SUFFIX,px.ads.linkedin.com,REJECT",
    "DOMAIN-SUFFIX,ct.pinterest.com,REJECT",
    "DOMAIN-SUFFIX,trk.pinterest.com,REJECT",
    "DOMAIN-SUFFIX,ads.pinterest.com,REJECT",

    # ── IP-блоки ──────────────────────────────────────────────────────────
    "IP-CIDR,74.125.0.0/16,REJECT,no-resolve",
    "IP-CIDR,209.85.128.0/17,REJECT,no-resolve",
    "IP-CIDR,68.67.128.0/21,REJECT,no-resolve",
    "IP-CIDR,87.248.100.0/21,REJECT,no-resolve",
    "IP-CIDR,213.180.193.0/24,REJECT,no-resolve",
    "IP-CIDR,94.100.180.0/22,REJECT,no-resolve",
]

# ─── Парсинг VLESS URL ────────────────────────────────────────────────────────

def load_configs(path: str) -> list[str]:
    return [
        l.strip() for l in Path(path).read_text(encoding="utf-8").splitlines()
        if l.strip() and not l.startswith("#")
    ]


def parse_vless_url(cfg: str) -> dict | None:
    try:
        if not cfg.startswith("vless://"):
            return None
        without_scheme = cfg[8:]
        if "@" not in without_scheme:
            return None
        uuid_part, rest = without_scheme.split("@", 1)
        if "?" not in rest:
            return None
        host_port, params_str = rest.split("?", 1)
        fragment = ""
        if "#" in host_port:
            host_port, fragment = host_port.split("#", 1)
        elif "#" in params_str:
            params_str, fragment = params_str.split("#", 1)
        host, port = host_port.rsplit(":", 1)
        params: dict[str, str] = {}
        for p in params_str.split("&"):
            if "=" in p:
                k, v = p.split("=", 1)
                params[k] = v
        return {
            "raw":         cfg,
            "uuid":        uuid_part,
            "host":        host,
            "port":        int(port),
            "security":    params.get("security", "none"),
            "sni":         params.get("sni", host),
            "flow":        params.get("flow", ""),
            "type":        params.get("type", "tcp"),
            "fp":          params.get("fp", "chrome"),
            "pbk":         params.get("pbk", ""),
            "sid":         params.get("sid", ""),
            "path":        params.get("path", ""),
            "host_header": params.get("host", ""),
        }
    except Exception:
        return None


# ─── Построение аутбаунда Xray ───────────────────────────────────────────────

def build_xray_outbound(parsed: dict, tag: str) -> dict:
    stream: dict = {"network": parsed["type"]}

    if parsed["security"] == "reality":
        stream["security"] = "reality"
        stream["realitySettings"] = {
            "serverName":  parsed["sni"],
            "publicKey":   parsed["pbk"],
            "shortId":     parsed["sid"],
            "fingerprint": parsed["fp"],
            "spiderX":     "/",
        }
    elif parsed["security"] == "tls":
        stream["security"] = "tls"
        stream["tlsSettings"] = {
            "serverName":  parsed["sni"],
            "fingerprint": parsed["fp"],
            "alpn":        ["h2", "http/1.1"],
        }
    else:
        stream["security"] = "none"

    if parsed["type"] == "ws":
        stream["wsSettings"] = {
            "path": parsed.get("path", "/"),
            "headers": {"Host": parsed.get("host_header") or parsed["host"]},
        }

    user: dict = {"id": parsed["uuid"], "encryption": "none", "level": 8}
    if parsed.get("flow"):
        user["flow"] = parsed["flow"]

    return {
        "tag":      tag,
        "protocol": "vless",
        "settings": {
            "vnext": [{"address": parsed["host"], "port": parsed["port"], "users": [user]}]
        },
        "streamSettings": stream,
    }


# ─── Описание сервера ─────────────────────────────────────────────────────────

def server_description(parsed: dict) -> str:
    sec = parsed.get("security", "none")
    transport = parsed.get("type", "tcp")
    parts = ["VLESS"]
    if sec == "reality":
        parts.append("Reality")
    elif sec == "tls":
        parts.append("TLS")
    if transport != "tcp":
        parts.append(transport.upper())
    return " + ".join(parts)


# ─── Имена конфигов ───────────────────────────────────────────────────────────

def country_name_ru(code: str) -> str:
    return COUNTRY_NAMES_RU.get(code, code)


def build_name(
    parsed: dict,
    index: int,
    entry_flag: str = ICON_UNKNOWN,
    entry_code: str = "",
    exit_code:  str = "",
    exit_flag:  str = ICON_UNKNOWN,
) -> str:
    num = f"#{index + 1}"
    has_entry = entry_code and entry_code != "XX"
    has_exit  = exit_code  and exit_code  != "XX"

    if has_exit and has_entry and exit_code != entry_code:
        ru_exit = country_name_ru(exit_code)
        return f"{entry_flag}→{exit_flag} {ru_exit} {num}"
    if has_exit:
        return f"{exit_flag} {country_name_ru(exit_code)} {num}"
    if has_entry:
        return f"{entry_flag} {country_name_ru(entry_code)} {num}"
    return f"{ICON_UNKNOWN} Сервер {num}"


def build_group_name(code: str, group_index: int | None = None) -> str:
    flag = COUNTRY_FLAGS.get(code, ICON_UNKNOWN)
    ru   = country_name_ru(code)
    base = f"{flag} {BRAND_AUTO_PREFIX}{ru}"
    return base if group_index is None else f"{base} {group_index}"


# ─── TCP-проверка ─────────────────────────────────────────────────────────────

def tcp_check(host: str, port: int, timeout: float = 3.0) -> float | None:
    try:
        t = time.monotonic()
        with socket.create_connection((host, port), timeout=timeout):
            return round((time.monotonic() - t) * 1000, 1)
    except Exception:
        return None


# ─── Определение страны ───────────────────────────────────────────────────────

def _extract_code(data: dict, extractor) -> str | None:
    try:
        code = extractor(data)
        if code and isinstance(code, str) and len(code) == 2:
            return code.upper()
    except Exception:
        pass
    return None


async def _query_one_geo(
    ip: str,
    url_fn,
    extractor,
    client: httpx.AsyncClient,
) -> str | None:
    try:
        url = url_fn(ip)
        r = await client.get(url, timeout=4.0, follow_redirects=True)
        if r.status_code != 200:
            return None
        data = r.json()
        return _extract_code(data, extractor)
    except Exception:
        return None


async def get_country_consensus(ip: str, client: httpx.AsyncClient) -> tuple[str, str]:
    tasks = [_query_one_geo(ip, url_fn, ext, client) for url_fn, ext in GEO_APIS]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    votes: dict[str, int] = {}
    for r in results:
        if isinstance(r, str) and r and r != "XX":
            votes[r] = votes.get(r, 0) + 1

    if not votes:
        return "XX", ICON_UNKNOWN

    winner = max(votes, key=votes.__getitem__)
    return winner, COUNTRY_FLAGS.get(winner, ICON_UNKNOWN)


async def resolve_ip(hostname: str) -> str | None:
    loop = asyncio.get_event_loop()
    try:
        infos = await loop.getaddrinfo(hostname, None, family=socket.AF_INET)
        if infos:
            return infos[0][4][0]
    except Exception:
        pass
    return None


# ─── Асинхронная проверка одного конфига ─────────────────────────────────────

async def _resolve_exit_country(
    sni: str,
    fallback_host: str,
    client: httpx.AsyncClient,
) -> tuple[str, str]:
    if not sni or sni == fallback_host:
        return "XX", ICON_UNKNOWN
    exit_ip = await resolve_ip(sni)
    if not exit_ip or exit_ip == fallback_host:
        return "XX", ICON_UNKNOWN
    return await get_country_consensus(exit_ip, client)


async def check_one(
    parsed: dict,
    tag: str,
    index: int,
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
) -> CheckResult:
    async with sem:
        loop = asyncio.get_event_loop()
        tcp_ms = await loop.run_in_executor(None, tcp_check, parsed["host"], parsed["port"])
        alive  = tcp_ms is not None

        if not alive:
            return CheckResult(
                tag=tag, name=f"{ICON_UNKNOWN} Сервер #{index + 1}",
                host=parsed["host"], port=parsed["port"],
                tcp_ms=None,
                country="XX",      flag=ICON_UNKNOWN,
                exit_country="XX", exit_flag=ICON_UNKNOWN,
                alive=False,
            )

        sni = parsed.get("sni", "")
        (entry_code, entry_flag), (exit_code, exit_flag) = await asyncio.gather(
            get_country_consensus(parsed["host"], client),
            _resolve_exit_country(sni, parsed["host"], client),
        )

        name = build_name(parsed, index, entry_flag, entry_code, exit_code, exit_flag)
        return CheckResult(
            tag=tag, name=name,
            host=parsed["host"], port=parsed["port"],
            tcp_ms=tcp_ms,
            country=entry_code,    flag=entry_flag,
            exit_country=exit_code, exit_flag=exit_flag,
            alive=True,
        )


# ══════════════════════════════════════════════════════════════════════════════
#  Ч Е Р Е З - П Р О К С И  П Р О В Е Р К А  С Т Р А Н Ы
# ══════════════════════════════════════════════════════════════════════════════

def build_test_xray_config(parsed: dict, socks_port: int) -> dict:
    outbound = build_xray_outbound(parsed, "proxy")
    return {
        "log": {"loglevel": "none"},
        "dns": {
            "servers": [
                "https://dns.adguard-dns.com/dns-query",
                "1.1.1.1",
                "8.8.8.8",
            ],
        },
        "inbounds": [{
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False},
        }],
        "outbounds": [outbound],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [{"type": "field", "network": "tcp,udp", "outboundTag": "proxy"}],
        },
    }


async def _wait_for_socks(
    host: str, port: int, timeout: float = 3.0,
) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=0.5,
            )
            writer.close()
            return True
        except (OSError, asyncio.TimeoutError):
            await asyncio.sleep(0.05)
    return False


async def _query_proxy_geo(
    url: str,
    extractor,
    socks_port: int,
    timeout: float = 4.0,
) -> str | None:
    cmd = [
        "curl", "-s", "--max-time", str(int(timeout)),
        "--socks5-hostname", f"127.0.0.1:{socks_port}",
        url,
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(
            proc.communicate(), timeout=timeout + 1,
        )
        if proc.returncode != 0:
            return None
        data = json.loads(stdout.decode())
        return _extract_code(data, extractor)
    except Exception:
        return None


async def get_proxy_country_consensus(
    socks_port: int, timeout: float = 5.0,
) -> tuple[str, str]:
    tasks = [
        _query_proxy_geo(url, ext, socks_port, timeout)
        for url, ext in PROXY_GEO_APIS
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    votes: dict[str, int] = {}
    for r in results:
        if isinstance(r, str) and r and r != "XX":
            votes[r] = votes.get(r, 0) + 1

    if not votes:
        return "XX", ICON_UNKNOWN
    winner = max(votes, key=votes.__getitem__)
    return winner, COUNTRY_FLAGS.get(winner, ICON_UNKNOWN)


async def check_country_through_proxy(
    parsed: dict, index: int,
) -> tuple[str, str]:
    socks_port = 10808 + (index % 200)
    config = build_test_xray_config(parsed, socks_port)
    xray_path = shutil.which("xray")
    if not xray_path:
        return "XX", ICON_UNKNOWN

    with tempfile.TemporaryDirectory(prefix="xray_test_") as tmpdir:
        config_path = Path(tmpdir) / "config.json"
        config_path.write_text(
            json.dumps(config, ensure_ascii=False), encoding="utf-8",
        )

        proc = await asyncio.create_subprocess_exec(
            xray_path, "run", "-c", str(config_path),
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )

        try:
            ready = await _wait_for_socks(
                "127.0.0.1", socks_port, timeout=5.0,
            )
            if not ready:
                return "XX", ICON_UNKNOWN
            await asyncio.sleep(0.5)
            return await get_proxy_country_consensus(
                socks_port, timeout=4.0,
            )
        finally:
            try:
                proc.terminate()
                await asyncio.wait_for(proc.wait(), timeout=3.0)
            except (asyncio.TimeoutError, ProcessLookupError):
                try:
                    proc.kill()
                    await proc.wait()
                except Exception:
                    pass


# ─── DNS конфиг Xray ─────────────────────────────────────────────────────────

def build_xray_dns() -> dict:
    """
    Блокирующие DNS-серверы в приоритете.
    Рекламные домены резолвятся через AdGuard → NXDOMAIN / 0.0.0.0.
    """
    return {
        "servers": [
            # AdGuard DNS — блокирует рекламу, трекеры, malware
            "94.140.14.14",
            "94.140.15.15",
            # NextDNS — блокирует рекламу и трекеры
            "45.90.28.231",
            "45.90.30.231",
            # Mullvad DNS с фильтрацией
            "194.242.2.3",
            # Cloudflare for Families (блокировка malware)
            "1.1.1.3",
            "1.0.0.3",
            # CleanBrowsing
            "185.228.168.9",
            "185.228.169.9",
            # Принудительный резолв рекламных доменов через AdGuard
            {
                "address": "94.140.14.14",
                "port":    53,
                "domains": ADBLOCK_DNS_DOMAINS,
            },
            # Резервные
            "1.1.1.1",
            "8.8.8.8",
        ]
    }


# ─── Скелет Xray-конфига ──────────────────────────────────────────────────────

def xray_skeleton(remarks: str, description: str = "") -> dict:
    cfg: dict = {"remarks": remarks}
    if description:
        cfg["meta"] = {"serverDescription": description}
    cfg.update({
        "log": {"loglevel": "warning", "dnsLog": False},
        "dns": build_xray_dns(),
        "policy": {
            "levels": {
                "8": {
                    "bufferSize":    3,
                    "connIdle":      300,
                    "downlinkOnly":  4,
                    "handshake":     3,
                    "uplinkOnly":    2,
                }
            }
        },
        "inbounds": [
            {
                "tag":      "socks-in",
                "listen":   "127.0.0.1",
                "port":     10808,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True},
                "sniffing": {
                    "enabled":      True,
                    "destOverride": ["tls", "http", "quic"],
                    "routeOnly":    True,
                    "metadataOnly": False,
                },
            },
            {
                "tag":      "http",
                "listen":   "127.0.0.1",
                "port":     10809,
                "protocol": "http",
                "settings": {"auth": "noauth", "udp": True},
                "sniffing": {
                    "enabled":      True,
                    "destOverride": ["tls", "http", "quic"],
                    "routeOnly":    True,
                    "metadataOnly": False,
                },
            },
        ],
    })
    return cfg


BURST_OBSERVATORY = {
    "pingConfig": {
        "connectivity": "http://connectivitycheck.platform.hicloud.com/generate_204",
        "destination":  "http://www.google.com/generate_204",
        "httpMethod":   "HEAD",
        "interval":     "5m",
        "sampling":     1,
        "timeout":      "10s",
    },
    "subjectSelector": ["proxy-"],
}


def routing_balancer(balancer_tag: str = "proxy-balancer") -> dict:
    return {
        "domainMatcher": "hybrid",
        "domainStrategy": "IPIfNonMatch",
        "balancers": [
            {
                "tag":      balancer_tag,
                "selector": ["proxy-"],
                "strategy": {"type": "leastPing"},
            }
        ],
        "rules": [
            # Адблок — первым
            ADBLOCK_RULE,
            {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"},
            {"type": "field", "network": "tcp,udp", "balancerTag": balancer_tag},
        ],
    }


DIRECT_OUTBOUNDS = [
    {"tag": "direct", "protocol": "freedom",   "settings": {"domainStrategy": "UseIP"}},
    {"tag": "block",  "protocol": "blackhole", "settings": {"response": {"type": "http"}}},
]


def auto_description(entries: list[tuple[dict, str, CheckResult]]) -> str:
    types = set()
    for parsed, _, _ in entries:
        types.add(server_description(parsed))
    return "Auto select | " + ", ".join(sorted(types))


# ─── Сборка AUTO-конфига ──────────────────────────────────────────────────────

def build_auto_config(
    remarks: str,
    entries: list[tuple[dict, str, CheckResult]],
    description: str = "",
) -> dict:
    cfg = xray_skeleton(remarks, description)
    cfg["burstObservatory"] = BURST_OBSERVATORY
    cfg["outbounds"] = (
        [build_xray_outbound(p, t) for p, t, _ in entries]
        + DIRECT_OUTBOUNDS
    )
    cfg["routing"] = routing_balancer()
    return cfg


# ─── Clash Meta конфиг ────────────────────────────────────────────────────────

def build_clash_config(entries: list[tuple[dict, str, CheckResult]]) -> str:
    proxies   = []
    names_all = []

    for parsed, tag, result in entries:
        name = result.name
        proxy: dict = {
            "name":   name,
            "type":   "vless",
            "server": parsed["host"],
            "port":   parsed["port"],
            "uuid":   parsed["uuid"],
            "udp":    True,
            "skip-cert-verify": False,
        }

        if parsed["type"] == "ws":
            proxy["network"] = "ws"
            proxy["ws-opts"] = {
                "path":    parsed.get("path", "/"),
                "headers": {"Host": parsed.get("host_header") or parsed["host"]},
            }
        else:
            proxy["network"] = "tcp"

        if parsed["security"] == "reality":
            proxy["tls"]                = True
            proxy["servername"]         = parsed["sni"] or parsed["host"]
            proxy["client-fingerprint"] = parsed.get("fp", "chrome")
            proxy["reality-opts"]       = {
                "public-key": parsed["pbk"],
                "short-id":   parsed.get("sid", ""),
            }
        elif parsed["security"] == "tls":
            proxy["tls"]                = True
            proxy["servername"]         = parsed["sni"] or parsed["host"]
            proxy["client-fingerprint"] = parsed.get("fp", "chrome")
        else:
            proxy["tls"] = False

        if parsed.get("flow"):
            proxy["flow"] = parsed["flow"]

        proxies.append(proxy)
        names_all.append(name)

    by_country: dict[str, list[str]] = {}
    for _, _, result in entries:
        if result.country != "XX":
            by_country.setdefault(result.country, []).append(result.name)

    country_groups = []
    for code, names in by_country.items():
        if len(names) >= 2:
            group_name = build_group_name(code)
            country_groups.append({
                "name":      group_name,
                "type":      "url-test",
                "proxies":   names,
                "url":       "https://www.gstatic.com/generate_204",
                "interval":  180,
                "tolerance": 30,
                "lazy":      True,
            })

    auto_group = {
        "name":      BRAND_AUTO,
        "type":      "url-test",
        "proxies":   names_all,
        "url":       "https://www.gstatic.com/generate_204",
        "interval":  180,
        "tolerance": 30,
        "lazy":      True,
    }

    select_proxies = [BRAND_AUTO] + [g["name"] for g in country_groups] + names_all
    select_group = {
        "name":    f"⚡ {BRAND} · Выбор",
        "type":    "select",
        "proxies": select_proxies,
    }

    clash_cfg = {
        "mixed-port":  7890,
        "allow-lan":   False,
        "mode":        "rule",
        "log-level":   "info",
        "ipv6":        False,
        # ── DNS Clash с блокирующими серверами ────────────────────────────
        "dns": {
            "enable":        True,
            "ipv6":          False,
            "enhanced-mode": "fake-ip",
            "fake-ip-range": "198.18.0.1/16",
            # Рекламные домены → fake-ip (уйдут в REJECT через rules)
            "fake-ip-filter": [
                "*.lan",
                "localhost.ptlogin2.qq.com",
                # Исключаем YouTube из fake-ip чтобы он работал нормально
                "*.youtube.com",
                "*.googlevideo.com",
                "*.ytimg.com",
                "*.ggpht.com",
                # VK, OK работают напрямую
                "*.vk.com",
                "*.ok.ru",
                # Telegram
                "*.telegram.org",
                "*.t.me",
            ],
            "nameserver": [
                # AdGuard DNS с блокировкой рекламы
                "https://dns.adguard-dns.com/dns-query",
                "https://94.140.14.14/dns-query",
                # NextDNS
                "https://dns.nextdns.io",
                # Cloudflare for Families
                "https://family.cloudflare-dns.com/dns-query",
                # Mullvad
                "https://base.dns.mullvad.net/dns-query",
            ],
            "fallback": [
                "https://dns.cloudflare.com/dns-query",
                "https://dns.google/dns-query",
            ],
            "fallback-filter": {
                "geoip":      True,
                "geoip-code": "CN",
                "ipcidr":     ["240.0.0.0/4"],
            },
        },
        "proxies":      proxies,
        "proxy-groups": [auto_group, select_group] + country_groups,
        # ── Rules: сначала адблок, потом остальное ────────────────────────
        "rules": CLASH_ADBLOCK_RULES + [
            "GEOIP,PRIVATE,DIRECT",
            f"MATCH,⚡ {BRAND} · Выбор",
        ],
    }

    return yaml.dump(clash_cfg, allow_unicode=True, sort_keys=False, default_flow_style=False)


# ─── MAIN ─────────────────────────────────────────────────────────────────────

async def main() -> None:
    raw_configs = load_configs(INPUT_FILE)
    print(f"[*] Загружено: {len(raw_configs)}")

    parsed_list: list[tuple[str, dict]] = []
    for cfg in raw_configs:
        p = parse_vless_url(cfg)
        if p:
            parsed_list.append((cfg, p))

    print(f"[*] Распарсено: {len(parsed_list)}")

    sem = asyncio.Semaphore(30)
    print(f"[*] Проверка...")

    async with httpx.AsyncClient(
        headers={"User-Agent": "Mozilla/5.0"},
        timeout=10.0,
    ) as client:
        tasks = [
            check_one(parsed, f"proxy-{i + 1}", i, client, sem)
            for i, (_, parsed) in enumerate(parsed_list)
        ]
        results: list[CheckResult] = await asyncio.gather(*tasks)

    alive = [(parsed_list[i][1], r) for i, r in enumerate(results) if r.alive]
    dead  = [(parsed_list[i][1], r) for i, r in enumerate(results) if not r.alive]
    alive.sort(key=lambda x: x[1].tcp_ms or 9999)

    print(f"[+] Живых: {len(alive)} | Мёртвых: {len(dead)}")

    # ── Through-proxy country verification for alive servers ──
    if shutil.which("xray"):
        print("[*] Проверка страны через прокси...")
        proxy_sem = asyncio.Semaphore(20)

        async def _proxy_check(i: int, parsed: dict):
            async with proxy_sem:
                country, flag = await check_country_through_proxy(parsed, i)
                return i, country, flag

        proxy_verified = 0
        proxy_changed = 0
        for i, country, flag in await asyncio.gather(*[
            _proxy_check(i, parsed) for i, (parsed, _) in enumerate(alive)
        ]):
            if country != "XX":
                old = alive[i][1].country
                alive[i][1].country = country
                alive[i][1].flag = flag
                alive[i][1].exit_country = country
                alive[i][1].exit_flag = flag
                if old != country:
                    proxy_changed += 1
                proxy_verified += 1

        print(f"   → {proxy_verified}/{len(alive)} прокси проверены ({proxy_changed} смена страны)")
    else:
        print("[!] xray не найден, проверка через прокси пропущена")

    log_lines = [
        f"{'─' * 60}",
        f"  {BRAND} VPN · Лог проверки",
        f"  Живых: {len(alive)}   Мёртвых: {len(dead)}",
        f"{'─' * 60}",
    ]
    for parsed, r in alive:
        ms_str = f"{r.tcp_ms:>6.1f}мс"
        if r.exit_country and r.exit_country != "XX" and r.exit_country != r.country:
            geo = (
                f"{r.flag}{country_name_ru(r.country):<12}"
                f" → {r.exit_flag}{country_name_ru(r.exit_country)}"
            )
        elif r.exit_country and r.exit_country != "XX":
            geo = f"{r.exit_flag} {country_name_ru(r.exit_country):<16}"
        elif r.country != "XX":
            geo = f"{r.flag} {country_name_ru(r.country):<16}"
        else:
            geo = f"{ICON_UNKNOWN} Неизвестно       "
        log_lines.append(f"  ✓  {geo}  {ms_str}  {r.host}:{r.port}")
    log_lines.append(f"{'─' * 60}")

    for parsed, r in dead:
        log_lines.append(f"  ✗  🇸🇴 Недоступен               TIMEOUT  {r.host}:{r.port}")
    Path(OUTPUT_LOG).write_text("\n".join(log_lines), encoding="utf-8")
    print("\n".join(log_lines[:20]))

    if not alive:
        print("[!] Нет доступных конфигов.")
        return

    country_counter: dict[str, int] = {}
    entries: list[tuple[dict, str, CheckResult]] = []
    global_index = 0

    for parsed, result in alive:
        new_tag    = f"proxy-{global_index + 1}"
        group_code = (
            result.exit_country
            if result.exit_country and result.exit_country != "XX"
            else result.country
        )
        country_counter[group_code] = country_counter.get(group_code, 0) + 1
        idx_in_country = country_counter[group_code]

        if result.exit_country and result.exit_country != "XX":
            if result.exit_country != result.country and result.country != "XX":
                result.name = (
                    f"{result.flag}→{result.exit_flag} "
                    f"{country_name_ru(result.exit_country)} #{idx_in_country}"
                )
            else:
                result.name = (
                    f"{result.exit_flag} "
                    f"{country_name_ru(result.exit_country)} #{idx_in_country}"
                )
        elif result.country and result.country != "XX":
            result.name = (
                f"{result.flag} "
                f"{country_name_ru(result.country)} #{idx_in_country}"
            )
        else:
            result.name = f"{ICON_UNKNOWN} Сервер #{global_index + 1}"

        entries.append((parsed, new_tag, result))
        global_index += 1

    by_country: dict[str, list[tuple[dict, str, CheckResult]]] = {}
    for item in entries:
        r    = item[2]
        code = r.exit_country if r.exit_country != "XX" else r.country
        if code != "XX":
            by_country.setdefault(code, []).append(item)

    GROUP_SIZE = 10
    # ── Только авто-конфиги, без одиночных серверов ───────────────────────
    auto_configs: list[dict] = []

    # 1. Глобальный авто (все серверы)
    auto_all = build_auto_config(
        BRAND_AUTO,
        entries,
        auto_description(entries),
    )
    auto_configs.append(auto_all)

    # 2. Авто по странам
    for code, items in sorted(by_country.items(), key=lambda x: -len(x[1])):
        if len(items) < 2:
            continue

        chunks = [items[i:i + GROUP_SIZE] for i in range(0, len(items), GROUP_SIZE)]
        for idx, chunk in enumerate(chunks, start=1):
            group_label = build_group_name(code, idx if len(chunks) > 1 else None)
            desc = auto_description(chunk)
            auto_configs.append(build_auto_config(group_label, chunk, desc))

        flag = COUNTRY_FLAGS.get(code, ICON_UNKNOWN)
        ru   = country_name_ru(code)
        print(f"   {flag} {ru}: {len(items)} серверов → {len(chunks)} групп(ы)")

    # ── Сохранение — только авто, без одиночных ───────────────────────────
    Path(OUTPUT_JSON).write_text(
        json.dumps(auto_configs, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"\n[+] {OUTPUT_JSON} — {len(auto_configs)} авто-конфигов (без одиночных серверов)")

    Path(OUTPUT_YAML).write_text(
        build_clash_config(entries),
        encoding="utf-8",
    )
    print(f"[+] {OUTPUT_YAML} — Clash Meta конфиг")


if __name__ == "__main__":
    asyncio.run(main())
