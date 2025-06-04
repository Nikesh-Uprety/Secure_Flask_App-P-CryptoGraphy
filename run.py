from app import create_app

app = create_app()

# Debugging: Print all routes and verify app creation
print("\n=== FLASK DEBUG INFORMATION ===")
print("App instance:", app)
print("Registered routes:")
if app.url_map.iter_rules():
    for rule in app.url_map.iter_rules():
        print(f"{rule.rule} -> {rule.endpoint}")
else:
    print("NO ROUTES REGISTERED!")
print("=============================\n")

if __name__ == '__main__':
    print("\n=== FINAL ROUTE CHECK ===")
    
    for rule in app.url_map.iter_rules():
        print(f"{rule.rule} -> {rule.endpoint}")

    app.run(
        host='0.0.0.0',
        port=5000,
        ssl_context='adhoc',
        debug=True  # Enable debug mode
    )