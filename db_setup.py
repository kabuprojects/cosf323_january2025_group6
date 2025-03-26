from pymongo import MongoClient

client = MongoClient("mongodb://localhost:27017/")
db = client["your_database"]

# Create collections
users_collection = db["users"]
verification_codes = db["verification_codes"]
email_otp = db["otp"]

print("Database and collections created successfully.")
