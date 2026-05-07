#!/usr/bin/env python3
"""
Clover.tech.netmon - Stripe Payment & License Fulfillment
==========================================================

Standalone Flask app that handles:
  1. Stripe Checkout session creation (Pro / Enterprise purchases)
  2. Stripe webhook to fulfill orders (generate + email license key)
  3. Customer portal redirect (manage subscription)

Setup:
  1. pip install flask stripe pyyaml
  2. Create products in Stripe Dashboard (or use the /admin/setup-products endpoint)
  3. Set environment variables or edit stripe_config.yaml
  4. Run: python stripe_handler.py
  5. Point Stripe webhook to https://yourdomain.com:8443/webhook/stripe

Environment variables (or set in stripe_config.yaml):
  STRIPE_SECRET_KEY      - sk_live_... or sk_test_...
  STRIPE_WEBHOOK_SECRET  - whsec_...
  STRIPE_PRO_PRICE_ID    - price_...  (monthly Pro price)
  STRIPE_ENT_PRICE_ID    - price_...  (monthly Enterprise price)
"""

import os
import sys
import json
import time
import hashlib
import hmac as hmac_mod
import secrets
import smtplib
import logging
import sqlite3
import datetime
import email.mime.text
import email.mime.multipart
from pathlib import Path

# ---------------------------------------------------------------------------
# Optional imports
# ---------------------------------------------------------------------------
try:
    import yaml
except ImportError:
    yaml = None

try:
    import stripe
except ImportError:
    stripe = None
    print("[ERROR] stripe package not installed. Run: pip install stripe")

try:
    from flask import Flask, request, jsonify, redirect
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False
    print("[ERROR] flask not installed. Run: pip install flask")

# ---------------------------------------------------------------------------
# Paths & Logging
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
STRIPE_DB = BASE_DIR / "stripe_orders.db"
STRIPE_CONFIG_FILE = BASE_DIR / "stripe_config.yaml"

log = logging.getLogger("stripe_handler")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(str(BASE_DIR / "stripe_handler.log"), encoding="utf-8"),
    ],
)

# ---------------------------------------------------------------------------
# License key generation (mirrors netmon.py logic exactly)
# ---------------------------------------------------------------------------
LICENSE_SECRET = b"clovertech-netmon-2026-salt"  # Must match netmon.py


def generate_license_key(tier_code, unique_id=None):
    """Generate a license key identical to netmon's validation logic."""
    if unique_id is None:
        unique_id = secrets.token_hex(4).upper()
    tier_code = tier_code.upper()
    payload = "%s-%s" % (tier_code, unique_id.upper())
    sig = hashlib.sha256(LICENSE_SECRET + payload.encode("utf-8")).hexdigest()[:16]
    return "%s-%s" % (payload, sig.upper())


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
_config = {}


def load_config():
    """Load config from stripe_config.yaml, then override with env vars."""
    global _config

    defaults = {
        "stripe_secret_key": "",
        "stripe_webhook_secret": "",
        "stripe_pro_price_id": "",
        "stripe_ent_price_id": "",
        "success_url": "https://myclover.tech/thank-you?session_id={CHECKOUT_SESSION_ID}",
        "cancel_url": "https://myclover.tech/#pricing",
        "host": "0.0.0.0",
        "port": 8443,
        "smtp": {
            "smtp_host": "",
            "smtp_port": 587,
            "use_tls": True,
            "username": "",
            "password": "",
            "from_addr": "sales@myclover.tech",
        },
    }

    _config = dict(defaults)

    # Load YAML config if exists
    if yaml and STRIPE_CONFIG_FILE.exists():
        try:
            with open(str(STRIPE_CONFIG_FILE), "r", encoding="utf-8") as f:
                file_cfg = yaml.safe_load(f) or {}
            for k, v in file_cfg.items():
                if isinstance(v, dict) and isinstance(_config.get(k), dict):
                    _config[k].update(v)
                else:
                    _config[k] = v
            log.info("Loaded config from %s", STRIPE_CONFIG_FILE)
        except Exception as e:
            log.warning("Error loading %s: %s", STRIPE_CONFIG_FILE, e)

    # Environment overrides (take priority)
    env_map = {
        "STRIPE_SECRET_KEY": "stripe_secret_key",
        "STRIPE_WEBHOOK_SECRET": "stripe_webhook_secret",
        "STRIPE_PRO_PRICE_ID": "stripe_pro_price_id",
        "STRIPE_ENT_PRICE_ID": "stripe_ent_price_id",
    }
    for env_key, cfg_key in env_map.items():
        val = os.environ.get(env_key, "")
        if val:
            _config[cfg_key] = val

    # Configure Stripe SDK
    if stripe and _config["stripe_secret_key"]:
        stripe.api_key = _config["stripe_secret_key"]
        log.info("Stripe API configured")
    elif stripe:
        log.warning("STRIPE_SECRET_KEY not set -- Stripe calls will fail")


# ---------------------------------------------------------------------------
# Order database
# ---------------------------------------------------------------------------
def init_stripe_db():
    """Initialize the orders database."""
    conn = sqlite3.connect(str(STRIPE_DB))
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            stripe_session_id TEXT UNIQUE,
            stripe_customer_id TEXT,
            stripe_subscription_id TEXT,
            customer_email TEXT,
            tier TEXT,
            license_key TEXT,
            amount_cents INTEGER,
            currency TEXT DEFAULT 'usd',
            status TEXT DEFAULT 'pending',
            fulfilled_at TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_orders_session ON orders(stripe_session_id);
        CREATE INDEX IF NOT EXISTS idx_orders_email ON orders(customer_email);
        CREATE INDEX IF NOT EXISTS idx_orders_key ON orders(license_key);
    """)
    conn.close()
    log.info("Orders database ready: %s", STRIPE_DB)


# ---------------------------------------------------------------------------
# Email delivery
# ---------------------------------------------------------------------------
def send_license_email(customer_email, tier, license_key):
    """Email the license key to the customer."""
    smtp_cfg = _config.get("smtp", {})
    if not smtp_cfg.get("smtp_host"):
        log.warning("SMTP not configured -- cannot email license key")
        log.info("MANUAL FULFILLMENT NEEDED: %s -> %s -> %s",
                 customer_email, tier, license_key)
        return False

    tier_label = "Pro" if tier == "pro" else "Enterprise"

    subject = "Your Clover.tech.netmon %s License Key" % tier_label

    body_text = """Thank you for purchasing Clover.tech.netmon %s!

Your license key:
%s

To activate:
1. Open your netmon dashboard (usually http://localhost:8080)
2. Go to Settings > License
3. Paste the key above and click "Activate"

All %s features will unlock immediately. No restart required.

If you have any questions, reply to this email or visit https://myclover.tech

-- The Clover.tech Team
""" % (tier_label, license_key, tier_label)

    body_html = """
<div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 600px; margin: 0 auto; background: #0a0e17; color: #e2e8f0; padding: 40px; border-radius: 12px;">
    <div style="text-align: center; margin-bottom: 30px;">
        <span style="font-size: 28px; font-weight: 700;">
            <span style="color: #22c55e;">Clover</span>.tech.netmon
        </span>
    </div>

    <h2 style="color: #22c55e; text-align: center; margin-bottom: 24px;">
        Thank you for your purchase!
    </h2>

    <p style="color: #94a3b8; text-align: center; margin-bottom: 24px;">
        You now have access to all <strong style="color: #e2e8f0;">%s</strong> features.
    </p>

    <div style="background: #1a1d2b; border: 1px solid #2a2d3a; border-radius: 8px; padding: 20px; text-align: center; margin-bottom: 24px;">
        <div style="color: #64748b; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px;">Your License Key</div>
        <div style="font-family: 'Courier New', monospace; font-size: 18px; font-weight: 700; color: #22c55e; letter-spacing: 1px; word-break: break-all;">
            %s
        </div>
    </div>

    <div style="background: #111827; border-radius: 8px; padding: 20px; margin-bottom: 24px;">
        <h3 style="color: #e2e8f0; font-size: 14px; margin-bottom: 12px;">How to activate:</h3>
        <ol style="color: #94a3b8; font-size: 14px; padding-left: 20px; line-height: 1.8;">
            <li>Open your netmon dashboard</li>
            <li>Go to <strong style="color: #e2e8f0;">Settings &gt; License</strong></li>
            <li>Paste the key above and click <strong style="color: #e2e8f0;">Activate</strong></li>
        </ol>
        <p style="color: #64748b; font-size: 12px; margin-top: 8px;">
            All features unlock immediately. No restart required.
        </p>
    </div>

    <div style="text-align: center; color: #475569; font-size: 12px; margin-top: 32px; border-top: 1px solid #1e293b; padding-top: 20px;">
        Questions? Reply to this email or visit
        <a href="https://myclover.tech" style="color: #22c55e; text-decoration: none;">myclover.tech</a>
    </div>
</div>
""" % (tier_label, license_key)

    msg = email.mime.multipart.MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = smtp_cfg.get("from_addr", "sales@myclover.tech")
    msg["To"] = customer_email
    msg.attach(email.mime.text.MIMEText(body_text, "plain"))
    msg.attach(email.mime.text.MIMEText(body_html, "html"))

    try:
        host = smtp_cfg.get("smtp_host", "localhost")
        port = smtp_cfg.get("smtp_port", 587)
        use_tls = smtp_cfg.get("use_tls", True)
        if use_tls:
            server = smtplib.SMTP(host, port, timeout=15)
            server.starttls()
        else:
            server = smtplib.SMTP(host, port, timeout=15)
        user = smtp_cfg.get("username", "")
        pwd = smtp_cfg.get("password", "")
        if user and pwd:
            server.login(user, pwd)
        server.sendmail(msg["From"], [customer_email], msg.as_string())
        server.quit()
        log.info("License email sent to %s", customer_email)
        return True
    except Exception as e:
        log.error("Failed to send license email to %s: %s", customer_email, e)
        return False


# ---------------------------------------------------------------------------
# Fulfillment logic
# ---------------------------------------------------------------------------
def fulfill_order(session_id, customer_email, tier, amount_cents=0,
                  currency="usd", customer_id="", subscription_id=""):
    """Generate license key, store order, and email customer."""
    # Generate key
    tier_code = "ENT" if tier == "enterprise" else "PRO"
    license_key = generate_license_key(tier_code)

    # Store order
    conn = sqlite3.connect(str(STRIPE_DB))
    try:
        conn.execute(
            """INSERT INTO orders
               (stripe_session_id, stripe_customer_id, stripe_subscription_id,
                customer_email, tier, license_key, amount_cents, currency,
                status, fulfilled_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'fulfilled', datetime('now'))""",
            (session_id, customer_id, subscription_id,
             customer_email, tier, license_key, amount_cents, currency)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        # Already fulfilled (duplicate webhook)
        row = conn.execute(
            "SELECT license_key, status FROM orders WHERE stripe_session_id = ?",
            (session_id,)
        ).fetchone()
        conn.close()
        if row:
            log.info("Order %s already fulfilled (key: %s)", session_id, row[0])
            return row[0]
        return None
    finally:
        conn.close()

    log.info("Order fulfilled: %s -> %s -> %s", customer_email, tier, license_key)

    # Email the key
    send_license_email(customer_email, tier, license_key)

    return license_key


# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------
def create_stripe_app():
    """Create the Stripe webhook + checkout Flask app."""
    app = Flask(__name__)

    # ----- Health check -----
    @app.route("/health")
    def health():
        return jsonify({"status": "ok", "service": "clovertech-stripe"})

    # ----- Create Checkout Session -----
    @app.route("/api/checkout", methods=["POST"])
    def create_checkout():
        """Create a Stripe Checkout session for Pro or Enterprise."""
        if not stripe:
            return jsonify({"error": "Stripe not configured"}), 500

        data = request.get_json(silent=True) or {}
        tier = data.get("tier", "pro").lower()

        if tier == "enterprise" or tier == "ent":
            price_id = _config.get("stripe_ent_price_id", "")
            tier = "enterprise"
        else:
            price_id = _config.get("stripe_pro_price_id", "")
            tier = "pro"

        if not price_id:
            return jsonify({"error": "Price ID not configured for tier: %s" % tier}), 500

        try:
            session = stripe.checkout.Session.create(
                payment_method_types=["card"],
                mode="subscription",
                line_items=[{"price": price_id, "quantity": 1}],
                success_url=_config.get("success_url",
                    "https://myclover.tech/thank-you?session_id={CHECKOUT_SESSION_ID}"),
                cancel_url=_config.get("cancel_url",
                    "https://myclover.tech/#pricing"),
                metadata={"tier": tier},
                allow_promotion_codes=True,
            )
            return jsonify({"checkout_url": session.url, "session_id": session.id})
        except Exception as e:
            log.error("Checkout creation failed: %s", e)
            return jsonify({"error": str(e)}), 400

    # ----- One-time purchase (alternative to subscription) -----
    @app.route("/api/checkout/onetime", methods=["POST"])
    def create_onetime_checkout():
        """Create a one-time payment Checkout session (perpetual license)."""
        if not stripe:
            return jsonify({"error": "Stripe not configured"}), 500

        data = request.get_json(silent=True) or {}
        tier = data.get("tier", "pro").lower()

        # For one-time purchases, use separate price IDs or create them inline
        onetime_prices = {
            "pro": _config.get("stripe_pro_onetime_price_id", ""),
            "enterprise": _config.get("stripe_ent_onetime_price_id", ""),
        }

        if tier in ("enterprise", "ent"):
            tier = "enterprise"
        else:
            tier = "pro"

        price_id = onetime_prices.get(tier, "")
        if not price_id:
            return jsonify({"error": "One-time price not configured for tier: %s" % tier}), 500

        try:
            session = stripe.checkout.Session.create(
                payment_method_types=["card"],
                mode="payment",
                line_items=[{"price": price_id, "quantity": 1}],
                success_url=_config.get("success_url",
                    "https://myclover.tech/thank-you?session_id={CHECKOUT_SESSION_ID}"),
                cancel_url=_config.get("cancel_url",
                    "https://myclover.tech/#pricing"),
                metadata={"tier": tier},
            )
            return jsonify({"checkout_url": session.url, "session_id": session.id})
        except Exception as e:
            log.error("One-time checkout failed: %s", e)
            return jsonify({"error": str(e)}), 400

    # ----- Stripe Webhook -----
    @app.route("/webhook/stripe", methods=["POST"])
    def stripe_webhook():
        """Handle Stripe webhook events."""
        payload = request.get_data(as_text=True)
        sig_header = request.headers.get("Stripe-Signature", "")

        webhook_secret = _config.get("stripe_webhook_secret", "")

        if webhook_secret:
            try:
                event = stripe.Webhook.construct_event(
                    payload, sig_header, webhook_secret
                )
            except stripe.error.SignatureVerificationError:
                log.warning("Webhook signature verification failed")
                return jsonify({"error": "Invalid signature"}), 400
            except Exception as e:
                log.error("Webhook error: %s", e)
                return jsonify({"error": str(e)}), 400
        else:
            # No webhook secret configured -- parse directly (dev mode only)
            log.warning("No webhook secret configured -- skipping signature check")
            try:
                event = json.loads(payload)
            except Exception:
                return jsonify({"error": "Invalid JSON"}), 400

        event_type = event.get("type", "") if isinstance(event, dict) else event["type"]
        log.info("Webhook event: %s", event_type)

        # Handle checkout completion
        if event_type == "checkout.session.completed":
            if isinstance(event, dict):
                session = event.get("data", {}).get("object", {})
            else:
                session = event["data"]["object"]

            session_id = session.get("id", "")
            customer_email = session.get("customer_details", {}).get("email", "")
            if not customer_email:
                customer_email = session.get("customer_email", "")
            metadata = session.get("metadata", {})
            tier = metadata.get("tier", "pro")
            amount = session.get("amount_total", 0)
            currency = session.get("currency", "usd")
            customer_id = session.get("customer", "")
            subscription_id = session.get("subscription", "")

            if customer_email:
                key = fulfill_order(
                    session_id=session_id,
                    customer_email=customer_email,
                    tier=tier,
                    amount_cents=amount,
                    currency=currency,
                    customer_id=customer_id,
                    subscription_id=subscription_id,
                )
                log.info("Fulfilled: %s -> %s (key: %s)", customer_email, tier, key)
            else:
                log.warning("No customer email in session %s", session_id)

        # Handle subscription cancellation (optional: log it)
        elif event_type == "customer.subscription.deleted":
            if isinstance(event, dict):
                sub = event.get("data", {}).get("object", {})
            else:
                sub = event["data"]["object"]
            sub_id = sub.get("id", "")
            log.info("Subscription cancelled: %s", sub_id)
            # Note: we don't revoke license keys automatically.
            # Keys work offline -- this is by design for self-hosted software.
            # Track cancellations for analytics.
            conn = sqlite3.connect(str(STRIPE_DB))
            conn.execute(
                """UPDATE orders SET status = 'cancelled'
                   WHERE stripe_subscription_id = ? AND status = 'fulfilled'""",
                (sub_id,)
            )
            conn.commit()
            conn.close()

        return jsonify({"received": True}), 200

    # ----- Customer Portal (manage subscription) -----
    @app.route("/api/portal", methods=["POST"])
    def customer_portal():
        """Create a Stripe Customer Portal session."""
        if not stripe:
            return jsonify({"error": "Stripe not configured"}), 500

        data = request.get_json(silent=True) or {}
        customer_id = data.get("customer_id", "")

        # Look up by email if no customer ID
        if not customer_id:
            customer_email = data.get("email", "")
            if customer_email:
                conn = sqlite3.connect(str(STRIPE_DB))
                row = conn.execute(
                    "SELECT stripe_customer_id FROM orders WHERE customer_email = ? "
                    "AND stripe_customer_id != '' ORDER BY id DESC LIMIT 1",
                    (customer_email,)
                ).fetchone()
                conn.close()
                if row:
                    customer_id = row[0]

        if not customer_id:
            return jsonify({"error": "Customer not found"}), 404

        try:
            portal = stripe.billing_portal.Session.create(
                customer=customer_id,
                return_url=_config.get("cancel_url", "https://myclover.tech"),
            )
            return jsonify({"portal_url": portal.url})
        except Exception as e:
            log.error("Portal creation failed: %s", e)
            return jsonify({"error": str(e)}), 400

    # ----- Admin: List orders -----
    @app.route("/api/admin/orders")
    def list_orders():
        """List all orders (admin use)."""
        # In production, protect this endpoint with auth
        conn = sqlite3.connect(str(STRIPE_DB))
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM orders ORDER BY id DESC LIMIT 100"
        ).fetchall()
        conn.close()
        return jsonify([dict(r) for r in rows])

    # ----- Admin: Lookup by email -----
    @app.route("/api/admin/lookup")
    def lookup_order():
        """Look up orders by email."""
        q = request.args.get("email", "")
        if not q:
            return jsonify({"error": "email parameter required"}), 400
        conn = sqlite3.connect(str(STRIPE_DB))
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM orders WHERE customer_email = ? ORDER BY id DESC",
            (q,)
        ).fetchall()
        conn.close()
        return jsonify([dict(r) for r in rows])

    # ----- Admin: Manual fulfillment -----
    @app.route("/api/admin/generate", methods=["POST"])
    def admin_generate():
        """Manually generate and optionally email a license key."""
        data = request.get_json(silent=True) or {}
        tier = data.get("tier", "pro").lower()
        customer_email = data.get("email", "")
        send_email = data.get("send_email", True)

        if tier in ("enterprise", "ent"):
            tier_code = "ENT"
            tier = "enterprise"
        else:
            tier_code = "PRO"
            tier = "pro"

        key = generate_license_key(tier_code)

        # Store
        conn = sqlite3.connect(str(STRIPE_DB))
        conn.execute(
            """INSERT INTO orders
               (stripe_session_id, customer_email, tier, license_key,
                amount_cents, status, fulfilled_at)
               VALUES (?, ?, ?, ?, 0, 'manual', datetime('now'))""",
            ("manual-%s" % secrets.token_hex(8), customer_email or "manual",
             tier, key)
        )
        conn.commit()
        conn.close()

        if customer_email and send_email:
            send_license_email(customer_email, tier, key)

        return jsonify({
            "license_key": key,
            "tier": tier,
            "email": customer_email,
            "email_sent": bool(customer_email and send_email),
        })

    # ----- Admin: Setup Stripe products (one-time helper) -----
    @app.route("/api/admin/setup-products", methods=["POST"])
    def setup_products():
        """Create Stripe products and prices. Run once during initial setup."""
        if not stripe:
            return jsonify({"error": "Stripe not configured"}), 500

        results = {}
        try:
            # Pro product
            pro_product = stripe.Product.create(
                name="Clover.tech.netmon Pro",
                description="Unlimited devices, network map, discovery scanner, "
                            "inventory, scheduled downtime, and more.",
                metadata={"tier": "pro"},
            )
            pro_price = stripe.Price.create(
                product=pro_product.id,
                unit_amount=2900,  # $29.00
                currency="usd",
                recurring={"interval": "month"},
            )
            results["pro"] = {
                "product_id": pro_product.id,
                "price_id": pro_price.id,
                "amount": "$29/mo",
            }

            # Enterprise product
            ent_product = stripe.Product.create(
                name="Clover.tech.netmon Enterprise",
                description="Everything in Pro plus NOC display, SLA reports, "
                            "user auth, custom plugins, SNMP deep polling, "
                            "and multi-channel notifications.",
                metadata={"tier": "enterprise"},
            )
            ent_price = stripe.Price.create(
                product=ent_product.id,
                unit_amount=9900,  # $99.00
                currency="usd",
                recurring={"interval": "month"},
            )
            results["enterprise"] = {
                "product_id": ent_product.id,
                "price_id": ent_price.id,
                "amount": "$99/mo",
            }

            log.info("Stripe products created: Pro=%s, Ent=%s",
                     pro_price.id, ent_price.id)

            return jsonify({
                "message": "Products and prices created successfully. "
                           "Update your stripe_config.yaml with these price IDs.",
                "products": results,
            })

        except Exception as e:
            log.error("Product setup failed: %s", e)
            return jsonify({"error": str(e)}), 400

    return app


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    log.info("Clover.tech.netmon Stripe Handler starting...")
    load_config()
    init_stripe_db()

    if not HAS_FLASK:
        log.error("Flask is required. Install: pip install flask")
        sys.exit(1)

    if not stripe:
        log.error("stripe package is required. Install: pip install stripe")
        sys.exit(1)

    app = create_stripe_app()
    host = _config.get("host", "0.0.0.0")
    port = _config.get("port", 8443)

    log.info("Stripe handler listening on http://%s:%d", host, port)
    log.info("Webhook endpoint: http://%s:%d/webhook/stripe", host, port)
    log.info("Checkout API: POST http://%s:%d/api/checkout", host, port)
    app.run(host=host, port=port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
