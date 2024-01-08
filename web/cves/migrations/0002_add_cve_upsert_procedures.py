from django.db import migrations


CVE_SQL = """
CREATE PROCEDURE cve_upsert(
    cve         text,
    created     timestamptz,
    updated     timestamptz,
    description text,
    title       text,
    metrics     jsonb,
    vendors     jsonb,
    weaknesses  jsonb
)
LANGUAGE plpgsql
AS $$
DECLARE
   _weakness  text;
   _vendors   text;
   _vendor    text;
   _vendor_id text;
   _product   text;
BEGIN
    -- add a new CVE or update an existing one
    INSERT INTO opencve_cves (id, created_at, updated_at, cve_id, description, title, vendors, weaknesses, metrics)
    VALUES(uuid_generate_v4(), created, updated, cve, description, title, vendors, weaknesses, metrics)
    ON CONFLICT (cve_id) DO
    UPDATE SET
      updated_at = updated,
      description = EXCLUDED.description,
      title = EXCLUDED.title,
      metrics = EXCLUDED.metrics,
      vendors = EXCLUDED.vendors,
      weaknesses = EXCLUDED.weaknesses;

    -- add the new weaknesses
    FOR _weakness IN SELECT * FROM json_array_elements_text(weaknesses::json)
    LOOP
      INSERT INTO opencve_cwes (id, created_at, updated_at, cwe_id)
      VALUES(uuid_generate_v4(), NOW(), NOW(), _weakness)
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
    cve         text,
    created     timestamptz,
    updated     timestamptz,
    description text,
    title       text,
    metrics     jsonb,
    vendors     jsonb,
    weaknesses  jsonb
);"""


class Migration(migrations.Migration):

    dependencies = [
        ('cves', '0001_initial'),
    ]

    operations = [
        migrations.RunSQL(sql=CVE_SQL, reverse_sql=CVE_REVERSE_SQL),
    ]
