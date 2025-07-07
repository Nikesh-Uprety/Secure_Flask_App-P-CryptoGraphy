from app import create_app
import os

app = create_app()

if __name__ == '__main__':
    print("\n=== FINAL ROUTE CHECK ===")
    for rule in app.url_map.iter_rules():
        print(f"{rule.rule} -> {rule.endpoint}")


cert_path = os.path.join('certs', 'localhost+2.pem')
key_path = os.path.join('certs', 'localhost+2-key.pem')

if os.path.exists(cert_path) and os.path.exists(key_path):
    context = (cert_path, key_path)
else:
    context = None  # Fallback to HTTP if certs are missing


app.run(
    ssl_context=context,
    host='0.0.0.0',
    port=5000,
    debug=True
)
