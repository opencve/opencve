from django.test import override_settings
from django.urls import reverse
from lxml import etree


def compare_xml(left, right):
    parser = etree.XMLParser(remove_blank_text=True)
    xml_left = etree.XML(left, parser=parser)
    xml_right = etree.XML(right.encode("utf-8"), parser=parser)
    return etree.tostring(xml_left) == etree.tostring(xml_right)


def test_sitemap(db, client, create_cve, open_raw_file):
    create_cve("CVE-2022-22965")
    create_cve("CVE-2024-31331")

    # Index Sitemap
    url = reverse("django.contrib.sitemaps.views.index")
    response = client.get(url)
    xml = open_raw_file("sitemap/index.xml")

    assert response.status_code == 200
    assert compare_xml(response.content, xml)

    # Cve Sitemap
    url = reverse("django.contrib.sitemaps.views.sitemap", kwargs={"section": "cves"})
    response = client.get(url)
    xml = open_raw_file("sitemap/cves.xml")

    assert response.status_code == 200
    assert compare_xml(response.content, xml)

    # Vendor Sitemap
    url = reverse(
        "django.contrib.sitemaps.views.sitemap", kwargs={"section": "vendors"}
    )
    response = client.get(url)
    xml = open_raw_file("sitemap/vendors.xml")

    assert response.status_code == 200
    assert compare_xml(response.content, xml)

    # Product Sitemap
    url = reverse(
        "django.contrib.sitemaps.views.sitemap", kwargs={"section": "products"}
    )
    response = client.get(url)
    xml = open_raw_file("sitemap/products.xml")

    assert response.status_code == 200
    assert compare_xml(response.content, xml)

    # Weakness Sitemap
    url = reverse(
        "django.contrib.sitemaps.views.sitemap", kwargs={"section": "weaknesses"}
    )
    response = client.get(url)
    xml = open_raw_file("sitemap/weaknesses.xml")

    assert response.status_code == 200
    assert compare_xml(response.content, xml)

    # Static Sitemap
    url = reverse("django.contrib.sitemaps.views.sitemap", kwargs={"section": "static"})
    response = client.get(url)
    xml = open_raw_file("sitemap/static.xml")

    assert response.status_code == 200
    assert compare_xml(response.content, xml)
