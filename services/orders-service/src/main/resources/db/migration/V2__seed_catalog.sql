-- Reference data shipped with the service (a real system would sync this from a catalog service).
INSERT INTO products (sku, name, unit_price, currency, active) VALUES
    ('KB-001',    'Mechanical keyboard',         89.00, 'USD', TRUE),
    ('MS-002',    'Wireless mouse',              29.50, 'USD', TRUE),
    ('MN-27-4K',  '27-inch 4K monitor',         329.99, 'USD', TRUE),
    ('HD-USB-C',  'USB-C docking station',      149.00, 'USD', TRUE),
    ('CB-HDMI-2', 'HDMI 2.1 cable (2 m)',        12.75, 'USD', TRUE),
    ('LEGACY-01', 'Discontinued serial adapter', 19.99, 'USD', FALSE);
