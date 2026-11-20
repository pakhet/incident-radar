"""Atom feed of public incidents, so anyone can subscribe anonymously."""

from __future__ import annotations

from xml.etree.ElementTree import Element, SubElement, tostring

ATOM = "http://www.w3.org/2005/Atom"


def atom(public: dict, base_url: str) -> bytes:
    # ElementTree escapes all text and attribute values, so headlines from
    # third-party feeds can't inject markup into ours.
    feed = Element("feed", xmlns=ATOM)
    SubElement(feed, "title").text = "Incident Radar: major security events"
    SubElement(
        feed, "subtitle"
    ).text = "Explainable, scored alerts for big security news, from KEV, NVD, vendors, and the security press."
    SubElement(feed, "id").text = f"{base_url}/"
    SubElement(feed, "link", href=f"{base_url}/feed.xml", rel="self")
    SubElement(feed, "link", href=f"{base_url}/")
    SubElement(feed, "updated").text = public.get("generated", "1970-01-01T00:00:00Z")

    for inc in public.get("incidents", [])[:50]:
        e = SubElement(feed, "entry")
        SubElement(e, "id").text = f"urn:incident-radar:{inc['id']}"
        SubElement(e, "title").text = f"[{inc['level'].upper()}] {inc['title']}"
        SubElement(e, "link", href=f"{base_url}/#i-{inc['id']}")
        SubElement(e, "updated").text = inc["last_seen"]
        SubElement(e, "published").text = inc["first_seen"]
        lines = [f"Score {inc['score']}/100 from {len(inc['sources'])} source(s): {', '.join(inc['sources'])}."]
        if inc["cves"]:
            lines.append("CVEs: " + ", ".join(inc["cves"]))
        lines += [f"{reason} (+{pts})" if pts >= 0 else f"{reason} ({pts})" for reason, pts in inc["breakdown"]]
        SubElement(e, "summary").text = "\n".join(lines)
    return b'<?xml version="1.0" encoding="utf-8"?>\n' + tostring(feed, encoding="unicode").encode()
