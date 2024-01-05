from django.db import migrations


CVE_SQL = """
CREATE PROCEDURE cve_upsert(
    cve     text,
    created timestamptz,
    updated timestamptz,
    summary text,
    cvss    jsonb,
    vendors jsonb,
    cwes    jsonb
)
LANGUAGE plpgsql
AS $$
DECLARE
   _cwe       text;
   _vendors   text;
   _vendor    text;
   _vendor_id text;
   _product   text;
BEGIN
    -- add a new CVE or update an existing one
    INSERT INTO opencve_cves (id, created_at, updated_at, cve_id, summary, vendors, cwes, cvss)
    VALUES(uuid_generate_v4(), created, updated, cve, summary, vendors, cwes, cvss)
    ON CONFLICT (cve_id) DO
    UPDATE SET
      updated_at = updated,
      summary = EXCLUDED.summary,
      cvss = EXCLUDED.cvss,
      vendors = EXCLUDED.vendors,
      cwes = EXCLUDED.cwes;

    -- add the new CWEs
    FOR _cwe IN SELECT * FROM json_array_elements_text(cwes::json)
    LOOP
      INSERT INTO opencve_cwes (id, created_at, updated_at, cwe_id)
      VALUES(uuid_generate_v4(), NOW(), NOW(), _cwe)
      ON CONFLICT (cwe_id) DO NOTHING;
    END LOOP;

    -- add the new Vendors & Products
    FOR _vendors IN SELECT * FROM json_array_elements_text(vendors::json)
    LOOP
      _vendor := split_part(_vendors, '$PRODUCT$', 1);
      _product := split_part(_vendors, '$PRODUCT$', 2);

      -- insert the vendor
      INSERT INTO opencve_vendors (id, created_at, updated_at, name)
      VALUES(uuid_generate_v4(), NOW(), NOW(), _vendor)
      ON CONFLICT (name) DO NOTHING;

      -- retrieve its ID
      SELECT id INTO _vendor_id FROM opencve_vendors WHERE name = _vendor;

      -- insert the product
      INSERT INTO opencve_products (id, created_at, updated_at, vendor_id, name)
      VALUES(uuid_generate_v4(), NOW(), NOW(), _vendor_id::uuid, _product)
      ON CONFLICT (name, vendor_id) DO NOTHING;
    END LOOP;
END;
$$;
"""
CVE_REVERSE_SQL = """
DROP PROCEDURE cve_upsert(
    cve     text,
    created timestamptz,
    updated timestamptz,
    summary text,
    cvss    jsonb,
    vendors jsonb,
    cwes    jsonb
);"""


class Migration(migrations.Migration):

    dependencies = [
        ('cves', '0001_initial'),
    ]

    operations = [
        migrations.RunSQL(sql=CVE_SQL, reverse_sql=CVE_REVERSE_SQL),
    ]
