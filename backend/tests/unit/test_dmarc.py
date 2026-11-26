import gzip
import io
import zipfile

import pytest

from app.modules.email.dmarc import parse_report

pytestmark = pytest.mark.req("EML-18")

AGGREGATE_XML = """<?xml version="1.0"?>
<feedback>
  <report_metadata><org_name>google.com</org_name><report_id>12345</report_id>
    <date_range><begin>1759881600</begin><end>1759968000</end></date_range></report_metadata>
  <policy_published><domain>mykcpl.com</domain><p>none</p></policy_published>
  <record><row><source_ip>45.33.22.11</source_ip><count>7</count>
      <policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row>
    <identifiers><header_from>mykcpl.com</header_from></identifiers></record>
  <record><row><source_ip>216.10.242.185</source_ip><count>40</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
    <identifiers><header_from>mykcpl.com</header_from></identifiers></record>
</feedback>"""


def test_parse_plain_xml():
    report = parse_report(AGGREGATE_XML.encode(), "report.xml")
    assert report.org_name == "google.com" and report.domain == "mykcpl.com" and report.policy == "none"
    rows = {r.source_ip: r for r in report.rows}
    assert rows["45.33.22.11"].count == 7 and rows["45.33.22.11"].dmarc_pass is False
    assert rows["216.10.242.185"].dmarc_pass is True


def test_parse_gzip():
    blob = gzip.compress(AGGREGATE_XML.encode())
    assert parse_report(blob, "report.xml.gz").domain == "mykcpl.com"


def test_parse_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("report.xml", AGGREGATE_XML)
    assert len(parse_report(buf.getvalue(), "report.zip").rows) == 2


def test_xml_bomb_rejected():
    bomb = ('<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">'
            '<!ENTITY lol2 "&lol;&lol;&lol;&lol;">]><feedback>&lol2;</feedback>')
    with pytest.raises(Exception):  # noqa: B017 - defusedxml raises on entity expansion
        parse_report(bomb.encode(), "bomb.xml")
