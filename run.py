from app import create_app
from config import Config


def print_startup_banner(db_path: str) -> None:
	print("=========================================")
	print("Firewall Rule Engine Started")
	print(f"API running at http://localhost:5000")
	print(f"Database: {db_path}")
	print("=========================================")


if __name__ == "__main__":
	# Create the Flask app and run
	app = create_app({"DATABASE_PATH": Config.DATABASE_PATH})
	print_startup_banner(Config.DATABASE_PATH)
	app.run(host="0.0.0.0", port=5000, debug=True)

