"""Timestamp conversion, normalization and presentation helpers.

All timestamps are stored in the case database as UTC strings in the sortable
form ``YYYY-MM-DD HH:MM:SS.ffffff``.  Presentation converts to the evidence or
examiner selected time zone.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone, tzinfo
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

UTC = timezone.utc
EPOCH_1601 = datetime(1601, 1, 1, tzinfo=UTC)
EPOCH_1970 = datetime(1970, 1, 1, tzinfo=UTC)
DB_FMT = "%Y-%m-%d %H:%M:%S.%f"

# Windows time zone key name -> IANA (CLDR windowsZones, territory 001)
WINDOWS_TZ = {
    "Dateline Standard Time": "Etc/GMT+12", "UTC-11": "Etc/GMT+11", "Hawaiian Standard Time": "Pacific/Honolulu",
    "Alaskan Standard Time": "America/Anchorage", "Pacific Standard Time": "America/Los_Angeles",
    "Pacific Standard Time (Mexico)": "America/Tijuana", "US Mountain Standard Time": "America/Phoenix",
    "Mountain Standard Time": "America/Denver", "Central America Standard Time": "America/Guatemala",
    "Central Standard Time": "America/Chicago", "Central Standard Time (Mexico)": "America/Mexico_City",
    "Canada Central Standard Time": "America/Regina", "SA Pacific Standard Time": "America/Bogota",
    "Eastern Standard Time": "America/New_York", "US Eastern Standard Time": "America/Indianapolis",
    "Venezuela Standard Time": "America/Caracas", "Atlantic Standard Time": "America/Halifax",
    "SA Western Standard Time": "America/La_Paz", "Pacific SA Standard Time": "America/Santiago",
    "Newfoundland Standard Time": "America/St_Johns", "E. South America Standard Time": "America/Sao_Paulo",
    "Argentina Standard Time": "America/Buenos_Aires", "SA Eastern Standard Time": "America/Cayenne",
    "Greenland Standard Time": "America/Godthab", "UTC-02": "Etc/GMT+2", "Azores Standard Time": "Atlantic/Azores",
    "Cape Verde Standard Time": "Atlantic/Cape_Verde", "UTC": "Etc/UTC", "Coordinated Universal Time": "Etc/UTC",
    "GMT Standard Time": "Europe/London", "Greenwich Standard Time": "Atlantic/Reykjavik",
    "Morocco Standard Time": "Africa/Casablanca", "W. Europe Standard Time": "Europe/Berlin",
    "Central Europe Standard Time": "Europe/Budapest", "Romance Standard Time": "Europe/Paris",
    "Central European Standard Time": "Europe/Warsaw", "W. Central Africa Standard Time": "Africa/Lagos",
    "Jordan Standard Time": "Asia/Amman", "GTB Standard Time": "Europe/Bucharest",
    "Middle East Standard Time": "Asia/Beirut", "Egypt Standard Time": "Africa/Cairo",
    "E. Europe Standard Time": "Europe/Chisinau", "Syria Standard Time": "Asia/Damascus",
    "South Africa Standard Time": "Africa/Johannesburg", "FLE Standard Time": "Europe/Kiev",
    "Israel Standard Time": "Asia/Jerusalem", "Kaliningrad Standard Time": "Europe/Kaliningrad",
    "Arabic Standard Time": "Asia/Baghdad", "Turkey Standard Time": "Europe/Istanbul",
    "Arab Standard Time": "Asia/Riyadh", "Belarus Standard Time": "Europe/Minsk",
    "Russian Standard Time": "Europe/Moscow", "E. Africa Standard Time": "Africa/Nairobi",
    "Iran Standard Time": "Asia/Tehran", "Arabian Standard Time": "Asia/Dubai", "Azerbaijan Standard Time": "Asia/Baku",
    "Mauritius Standard Time": "Indian/Mauritius", "Georgian Standard Time": "Asia/Tbilisi",
    "Caucasus Standard Time": "Asia/Yerevan", "Afghanistan Standard Time": "Asia/Kabul",
    "West Asia Standard Time": "Asia/Tashkent", "Ekaterinburg Standard Time": "Asia/Yekaterinburg",
    "Pakistan Standard Time": "Asia/Karachi", "India Standard Time": "Asia/Kolkata",
    "Sri Lanka Standard Time": "Asia/Colombo", "Nepal Standard Time": "Asia/Katmandu",
    "Central Asia Standard Time": "Asia/Almaty", "Bangladesh Standard Time": "Asia/Dhaka",
    "Myanmar Standard Time": "Asia/Rangoon", "SE Asia Standard Time": "Asia/Bangkok",
    "N. Central Asia Standard Time": "Asia/Novosibirsk", "China Standard Time": "Asia/Shanghai",
    "North Asia Standard Time": "Asia/Krasnoyarsk", "Singapore Standard Time": "Asia/Singapore",
    "W. Australia Standard Time": "Australia/Perth", "Taipei Standard Time": "Asia/Taipei",
    "Ulaanbaatar Standard Time": "Asia/Ulaanbaatar", "North Asia East Standard Time": "Asia/Irkutsk",
    "Tokyo Standard Time": "Asia/Tokyo", "Korea Standard Time": "Asia/Seoul",
    "Cen. Australia Standard Time": "Australia/Adelaide", "AUS Central Standard Time": "Australia/Darwin",
    "E. Australia Standard Time": "Australia/Brisbane", "AUS Eastern Standard Time": "Australia/Sydney",
    "West Pacific Standard Time": "Pacific/Port_Moresby", "Tasmania Standard Time": "Australia/Hobart",
    "Yakutsk Standard Time": "Asia/Yakutsk", "Vladivostok Standard Time": "Asia/Vladivostok",
    "Central Pacific Standard Time": "Pacific/Guadalcanal", "Magadan Standard Time": "Asia/Magadan",
    "New Zealand Standard Time": "Pacific/Auckland", "UTC+12": "Etc/GMT-12", "Fiji Standard Time": "Pacific/Fiji",
    "Tonga Standard Time": "Pacific/Tongatapu", "Samoa Standard Time": "Pacific/Apia",
    "Line Islands Standard Time": "Pacific/Kiritimati",
}


def resolve_windows_tz(key_name: str | None, bias_minutes: int | None = None) -> tzinfo:
    """Map a Windows ``TimeZoneKeyName`` to a tzinfo, falling back to a fixed offset."""
    if key_name:
        iana = WINDOWS_TZ.get(key_name.strip())
        if iana:
            try:
                return ZoneInfo(iana)
            except ZoneInfoNotFoundError:
                pass
        try:
            return ZoneInfo(key_name)
        except (ZoneInfoNotFoundError, ValueError):
            pass
    if bias_minutes is not None:
        if bias_minutes > 0x7FFFFFFF:
            bias_minutes -= 0x100000000
        return timezone(timedelta(minutes=-bias_minutes))
    return UTC


def get_tz(name: str | None) -> tzinfo:
    if not name or name.upper() == "UTC":
        return UTC
    if name in WINDOWS_TZ:
        return resolve_windows_tz(name)
    m = re.fullmatch(r"UTC([+-])(\d{1,2}):?(\d{2})?", name.strip())
    if m:
        delta = timedelta(hours=int(m.group(2)), minutes=int(m.group(3) or 0))
        return timezone(delta if m.group(1) == "+" else -delta)
    try:
        return ZoneInfo(name)
    except Exception:
        return UTC


def to_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def valid(dt: datetime | None) -> bool:
    if dt is None:
        return False
    u = to_utc(dt)
    return datetime(1980, 1, 1, tzinfo=UTC) < u < datetime(2100, 1, 1, tzinfo=UTC)


def db_ts(dt: datetime | None) -> str | None:
    """UTC database representation, None for missing/implausible values."""
    if not valid(dt):
        return None
    return to_utc(dt).strftime(DB_FMT)


def from_db(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.strptime(s, DB_FMT).replace(tzinfo=UTC)
    except ValueError:
        try:
            return to_utc(datetime.fromisoformat(s.replace("Z", "+00:00")))
        except ValueError:
            return None


def filetime(value: int) -> datetime | None:
    if not value or value < 0 or value > 0x7FFFFFFFFFFFFFFF:
        return None
    try:
        return EPOCH_1601 + timedelta(microseconds=value / 10)
    except OverflowError:
        return None


def webkit(value: int) -> datetime | None:
    if not value:
        return None
    try:
        return EPOCH_1601 + timedelta(microseconds=value)
    except OverflowError:
        return None


def unix(value: float) -> datetime | None:
    if not value:
        return None
    try:
        return EPOCH_1970 + timedelta(seconds=value)
    except OverflowError:
        return None


def prtime(value: int) -> datetime | None:
    if not value:
        return None
    return unix(value / 1_000_000)


def parse_any(value) -> datetime | None:
    """Best effort parsing of user supplied / imported timestamps (assumed UTC if naive)."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return to_utc(value)
    if isinstance(value, (int, float)):
        v = float(value)
        if v > 1e17:
            return filetime(int(v))
        if v > 1e14:
            return webkit(int(v)) if v > 1.1e16 else unix(v / 1e6)
        if v > 1e11:
            return unix(v / 1000)
        if v > 1e8:
            return unix(v)
        # Excel serial date
        if 20000 < v < 80000:
            return datetime(1899, 12, 30, tzinfo=UTC) + timedelta(days=v)
        return None
    s = str(value).strip()
    if re.fullmatch(r"\d+(\.\d+)?", s):
        return parse_any(float(s))
    try:
        return to_utc(datetime.fromisoformat(s.replace("Z", "+00:00")))
    except ValueError:
        pass
    try:
        from dateutil import parser as du

        return to_utc(du.parse(s, dayfirst=False))
    except Exception:
        return None


def fmt(dt: datetime | str | None, tz: tzinfo | None = None, seconds: bool = True, with_zone: bool = True) -> str:
    if isinstance(dt, str):
        dt = from_db(dt)
    if dt is None:
        return ""
    tz = tz or UTC
    local = to_utc(dt).astimezone(tz)
    s = local.strftime("%Y-%m-%d %H:%M:%S" if seconds else "%Y-%m-%d %H:%M")
    if with_zone:
        s += " " + zone_label(local)
    return s


def zone_label(local: datetime) -> str:
    off = local.utcoffset() or timedelta(0)
    if off == timedelta(0):
        return "UTC"
    total = int(off.total_seconds() // 60)
    sign = "+" if total >= 0 else "-"
    total = abs(total)
    return f"UTC{sign}{total // 60:02d}:{total % 60:02d}"


def fmt_dual(dt, tz: tzinfo | None) -> str:
    """'2026-09-14 05:32:13 UTC (11:02:13 UTC+05:30)'."""
    if isinstance(dt, str):
        dt = from_db(dt)
    if dt is None:
        return ""
    base = fmt(dt, UTC)
    if tz is None or tz == UTC:
        return base
    local = to_utc(dt).astimezone(tz)
    if local.utcoffset() == timedelta(0):
        return base
    return f"{base} ({local.strftime('%Y-%m-%d %H:%M:%S')} {zone_label(local)})"


def duration_text(seconds: float) -> str:
    seconds = int(max(0, seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h {m:02d}m"
    if m:
        return f"{m}m {s:02d}s"
    return f"{s}s"


def in_window(ts: str | datetime | None, start: datetime | None, end: datetime | None) -> bool:
    if isinstance(ts, str):
        ts = from_db(ts)
    if ts is None:
        return False
    ts = to_utc(ts)
    if start and ts < to_utc(start):
        return False
    if end and ts > to_utc(end):
        return False
    return True
