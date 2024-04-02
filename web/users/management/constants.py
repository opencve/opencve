V1_USERS_SQL = """
SELECT
  id,
  created_at,
  updated_at,
  username,
  password,
  email,
  first_name,
  last_name,
  admin,
  filters_notifications
FROM
  users
WHERE
  email_confirmed_at IS NOT NULL;
"""

V1_VENDORS_SQL = """
SELECT
  vendors.name
FROM
  vendors
  JOIN users_vendors ON vendors.id = users_vendors.vendor_id
WHERE
  users_vendors.user_id = %(user_id)s;
"""

V1_PRODUCTS_SQL = """
SELECT
  vendors.name,
  products.name
FROM
  products
  JOIN users_products ON products.id = users_products.product_id
  JOIN vendors ON products.vendor_id = vendors.id
WHERE
  users_products.user_id = %(user_id)s;
"""
