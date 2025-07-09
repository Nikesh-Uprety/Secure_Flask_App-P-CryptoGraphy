from app import create_app
import os

app = create_app()

if __name__ == '__main__':
    print("\n=== FINAL ROUTE CHECK ===")
    for rule in app.url_map.iter_rules():
        print(f"{rule.rule} -> {rule.endpoint}")

    use_ssl = os.environ.get("USE_SSL", "false").lower() == "true"
    context = None
    if use_ssl:
        cert_path = os.path.join('certs', 'localhost+2.pem')
        key_path = os.path.join('certs', 'localhost+2-key.pem')
        if os.path.exists(cert_path) and os.path.exists(key_path):
            context = (cert_path, key_path)

    port = int(os.environ.get("PORT", 5000))  # Use dynamic port from Render
    app.run(
        ssl_context=context,
        host='0.0.0.0',
        port=port,
        debug=True
    )
