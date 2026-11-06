from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, HttpUrl
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import requests
import socket
import ipaddress
import time
import re

app = FastAPI(title="REALITYX")

app.mount(
    "/static",
    StaticFiles(directory="static"),
    name="static"
)

HEADERS = {
    "User-Agent": "REALITYX-Audit/1.0"
}


class AuditRequest(BaseModel):
    url: HttpUrl
    check_links: bool = True
    max_links: int = 20


def validate_url(url):
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise HTTPException(
            status_code=400,
            detail="Only HTTP and HTTPS URLs are supported."
        )

    host = parsed.hostname

    if not host:
        raise HTTPException(
            status_code=400,
            detail="Invalid hostname."
        )

    if host == "localhost" or host.endswith(
        (".localhost", ".local")
    ):
        raise HTTPException(
            status_code=400,
            detail="Local addresses are not supported."
        )

    try:
        addresses = socket.getaddrinfo(host, None)

        for item in addresses:
            ip = ipaddress.ip_address(item[4][0])

            if not ip.is_global:
                raise HTTPException(
                    status_code=400,
                    detail="Private addresses are not allowed."
                )

    except socket.gaierror:
        raise HTTPException(
            status_code=400,
            detail="Could not resolve hostname."
        )


def fetch_page(url):
    validate_url(url)

    try:
        response = requests.get(
            url,
            headers=HEADERS,
            timeout=12,
            allow_redirects=True
        )

        validate_url(response.url)

        return response

    except HTTPException:
        raise

    except requests.RequestException as error:
        raise HTTPException(
            status_code=502,
            detail=f"Website request failed: {error}"
        )


def check_link(url):
    try:
        validate_url(url)

        response = requests.head(
            url,
            headers=HEADERS,
            timeout=8,
            allow_redirects=True
        )

        if response.status_code in (403, 405, 501):
            response.close()

            response = requests.get(
                url,
                headers=HEADERS,
                timeout=8,
                allow_redirects=True,
                stream=True
            )

        status = response.status_code
        redirected = len(response.history) > 0
        final_url = response.url

        response.close()

        return {
            "url": url,
            "status": status,
            "status_code": status,
            "ok": status < 400,
            "redirected": redirected,
            "final_url": final_url
        }

    except Exception as e:
        return {
            "url": url,
            "status": None,
            "status_code": None,
            "ok": False,
            "redirected": False,
            "final_url": None,
            "error": str(e)
        }


@app.get("/")
def home():
    return FileResponse("static/index.html")


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "app": "REALITYX"
    }


@app.post("/api/audit")
def audit(data: AuditRequest):
    started = time.time()

    url = str(data.url)

    response = fetch_page(url)

    if response.status_code >= 400:
        raise HTTPException(
            status_code=502,
            detail=f"Website returned HTTP {response.status_code}."
        )

    content_type = response.headers.get(
        "content-type", ""
    )

    if "text/html" not in content_type.lower():
        raise HTTPException(
            status_code=400,
            detail="The URL did not return an HTML page."
        )

    soup = BeautifulSoup(
        response.content[:2_000_000],
        "html.parser"
    )

    title_element = soup.find("title")

    title = (
        title_element.get_text(" ", strip=True)
        if title_element else ""
    )

    images = soup.find_all("img")

    missing_alt = sum(
        1 for image in images
        if not image.get("alt", "").strip()
    )

    headings = soup.find_all(
        re.compile(r"^h[1-6]$")
    )

    forms = soup.find_all("form")

    findings = []

    def add_finding(severity, title, detail, recommendation):
        findings.append({
            "severity": severity,
            "title": title,
            "detail": detail,
            "recommendation": recommendation
        })

    add_finding(
        "passed",
        f"HTTP {response.status_code}",
        "The website returned a successful response.",
        "No action required for this check."
    )

    if title:
        add_finding(
            "passed",
            "Page title found",
            f"Title: {title[:140]}",
            "Keep the page title descriptive."
        )
    else:
        add_finding(
            "warning",
            "Missing page title",
            "No non-empty title element was found.",
            "Add a descriptive title element inside the HTML head."
        )

    description = soup.find(
        "meta",
        attrs={"name": re.compile("^description$", re.I)}
    )

    if description:
        add_finding(
            "passed",
            "Meta description found",
            "A description meta tag is present.",
            "Keep the description relevant to the page."
        )
    else:
        add_finding(
            "info",
            "Meta description missing",
            "A description meta tag was not found.",
            "Consider adding a concise meta description."
        )

    if missing_alt:
        add_finding(
            "warning",
            f"{missing_alt} image(s) missing alt text",
            "Some images do not have alternative text.",
            "Add meaningful alt text or empty alt text for decorative images."
        )
    else:
        add_finding(
            "passed",
            "Image alt-text check",
            f"Checked {len(images)} images.",
            "Ensure image descriptions are meaningful."
        )

    if not soup.find("h1"):
        add_finding(
            "info",
            "No H1 heading found",
            "No top-level H1 heading was found in the HTML.",
            "Add a clear page heading when appropriate."
        )
    else:
        add_finding(
            "passed",
            "H1 heading found",
            "At least one H1 heading is present.",
            "Maintain a clear heading hierarchy."
        )

    if forms:
        add_finding(
            "passed",
            f"{len(forms)} form(s) detected",
            "Forms were found in the HTML. They were not submitted.",
            "Test form validation separately in an authorized environment."
        )
    else:
        add_finding(
            "info",
            "No HTML forms detected",
            "No form elements were found in the downloaded HTML.",
            "Dynamically rendered forms may not appear in raw HTML."
        )
    links = []
    seen = set()

    source_host = (urlparse(response.url).hostname or "").lower()

    if source_host.startswith("www."):
        source_host = source_host[4:]

    for element in soup.find_all("a", href=True):
        href = element["href"].strip()

        if href.startswith(("#", "mailto:", "tel:", "javascript:")):
            continue

        absolute = urljoin(response.url, href)
        parsed_url = urlparse(absolute)

        if parsed_url.scheme not in ("http", "https"):
            continue

        if absolute not in seen:
            seen.add(absolute)

            target_host = (parsed_url.hostname or "").lower()

            if target_host.startswith("www."):
                target_host = target_host[4:]

            link_type = (
                "internal" if target_host == source_host else "external"
            )

            links.append({
                "url": absolute,
                "text": element.get_text(" ", strip=True) or "(no link text)",
                "type": link_type
            })

        link_results = []

        if data.check_links:
            max_links = max(1, min(data.max_links, 30))

            for link in links[:max_links]:
                result = check_link(link["url"])
                link_results.append({**link, **result})

        broken = sum(1 for link in link_results if not link.get("ok", False))

        working = sum(
            1 for link in link_results
            if link.get("ok") and not link.get("redirected")
        )

        redirected = sum(
            1 for link in link_results
            if link.get("ok") and link.get("redirected")
        )

        internal_count = sum(1 for link in links if link["type"] == "internal")
        external_count = sum(1 for link in links if link["type"] == "external")

        if data.check_links:
            add_finding(
                "warning" if broken else "passed",
                f"Link check: {broken} issue(s)",
                (
                    f"Checked {len(link_results)} of {len(links)} unique links. "
                    f"Internal: {internal_count}, External: {external_count}. "
                    f"Working: {working}, Redirected: {redirected}."
                ),
                "Review flagged links manually; some websites block automated checks."
            )
        else:
            add_finding(
                "info",
                "Link checking skipped",
                f"Found {len(links)} unique links, but link checking was disabled.",
                "Enable sample link checking to inspect link responses."
            )

        score = 100

        for finding in findings:
                if finding["severity"] == "critical":
                    score -= 25
                elif finding["severity"] == "warning":
                    score -= 10
                elif finding["severity"] == "info":
                    score -= 3

        score = max(0, score)
    seo_score = 100

    if not title:
        seo_score -= 20

    if not description:
        seo_score -= 10

    if not soup.find("h1"):
        seo_score -= 10

    accessibility_score = max(
        0,
        100 - min(50, missing_alt * 10)
    )

    link_score = None

    if link_results:
        link_score = round(
            sum(1 for link in link_results if link.get("ok"))
            / len(link_results) * 100
        )

    quality_breakdown = {
        "overall": score,
        "seo": max(0, seo_score),
        "accessibility": accessibility_score,
        "link_health": link_score
    }
    return{
            "quality_breakdown": quality_breakdown,
                "url": url,
                "final_url": response.url,
                "status_code": response.status_code,
                "page_title": title or "(missing)",
                "response_time_seconds": round(
                    response.elapsed.total_seconds(), 2
                ),
                "audit_duration_seconds": round(
                    time.time() - started, 2
                ),
                "html_size_kb": round(
                    len(response.content) / 1024, 1
                ),
                "score": score,
                "summary": {
                    "checks": len(findings),
                    "passed": sum(
                        1 for f in findings
                        if f["severity"] == "passed"
                    ),
                    "warnings": sum(
                        1 for f in findings
                        if f["severity"] == "warning"
                    ),
                    "info": sum(
                        1 for f in findings
                        if f["severity"] == "info"
                    ),
                    "links_found": len(links),
                    "links_checked": len(link_results),
                    "internal_links": internal_count,
"external_links": external_count,
"working_links": working,
"broken_links": broken,
"redirected_links": redirected,
                    "images": len(images),
                    "images_missing_alt": missing_alt,
                    "forms_found": len(forms),
                    "headings_found": len(headings)
                },
                "findings": findings,
                "bug_report": [
            {
                "severity": item["severity"],
                "issue": item["title"],
                "details": item["detail"],
                "solution": item["recommendation"]
            }
            for item in findings
            if item["severity"] in ("critical", "warning")
        ],
                "links": link_results
            }
