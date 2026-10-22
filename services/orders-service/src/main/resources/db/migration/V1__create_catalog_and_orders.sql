-- Catalog: prices are owned by the server, never supplied by clients.
CREATE TABLE products (
    sku         VARCHAR(64)    PRIMARY KEY,
    name        VARCHAR(200)   NOT NULL,
    unit_price  NUMERIC(12, 2) NOT NULL CHECK (unit_price > 0),
    currency    VARCHAR(3)     NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    active      BOOLEAN        NOT NULL DEFAULT TRUE
);

CREATE TABLE orders (
    id            UUID           PRIMARY KEY,
    customer_id   VARCHAR(64)    NOT NULL,
    status        VARCHAR(16)    NOT NULL
                  CHECK (status IN ('PENDING', 'CONFIRMED', 'SHIPPED', 'DELIVERED', 'CANCELLED')),
    currency      VARCHAR(3)     NOT NULL,
    total_amount  NUMERIC(12, 2) NOT NULL CHECK (total_amount >= 0),
    created_at    TIMESTAMPTZ    NOT NULL,
    updated_at    TIMESTAMPTZ    NOT NULL,
    version       BIGINT         NOT NULL DEFAULT 0
);

-- Serves "my orders, newest first" without a sort.
CREATE INDEX orders_customer_created_idx ON orders (customer_id, created_at DESC);
CREATE INDEX orders_status_created_idx ON orders (status, created_at DESC);

CREATE TABLE order_lines (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    order_id      UUID           NOT NULL REFERENCES orders (id) ON DELETE CASCADE,
    line_number   INTEGER        NOT NULL,
    sku           VARCHAR(64)    NOT NULL REFERENCES products (sku),
    product_name  VARCHAR(200)   NOT NULL,
    quantity      INTEGER        NOT NULL CHECK (quantity BETWEEN 1 AND 1000),
    unit_price    NUMERIC(12, 2) NOT NULL CHECK (unit_price > 0),
    CONSTRAINT order_lines_order_line_uk UNIQUE (order_id, line_number)
);
