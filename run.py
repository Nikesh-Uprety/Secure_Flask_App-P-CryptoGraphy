from app import create_app

app = create_app()


if __name__ == '__main__':
    print("\n=== FINAL ROUTE CHECK ===")
    for rule in app.url_map.iter_rules():
        print(f"{rule.rule} -> {rule.endpoint}")

    # Run Flask with mkcert HTTPS cert and key
    app.run(
        ssl_context=('certs/localhost+2.pem', 'certs/localhost+2-key.pem'),  #  mkcert files
        host='0.0.0.0',  # Listen on all interfaces
        port=5000,
        debug=False
    )
