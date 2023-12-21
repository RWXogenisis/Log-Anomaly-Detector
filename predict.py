import pandas as pd
from joblib import load

# Load the trained model
model_path = "./your_model_path.joblib"  # Replace with the path to your saved model
model = load(model_path)

# Load the new CSV file for prediction
new_data_path = "./server logs/server.csv"  # Replace with the path to your new CSV file
new_data = pd.read_csv(new_data_path)

# Drop unnecessary datetime, sdate, and edate columns
new_data = new_data.drop(columns=["datetime", "sdate", "edate"])

# Make predictions
predictions = model.predict(new_data)

# Add predictions to the new_data DataFrame
new_data["Predicted_IDS_Decision"] = predictions

# Save the results to a new CSV file
output_csv_path = "./output_predictions.csv"  # Replace with the desired path and filename
new_data.to_csv(output_csv_path, index=False)
