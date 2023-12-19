# Log-Anomaly-Detector
This is the public repo for Team Equators for the IISF hackathon

A short Description of File Contents is as follows:
✅ Server Logs : It contains the .csv file which has data that has been tokenized from the given Server Logs Dataset
✅ FireWall Logs : It contains the .csv file which has data that has been tokenized from the given FireWall Logs Dataset
✅ Mitre-framework-scraped.py : Python script to automate Web Scraping of Mitigation policies from Mitre Attack.org
✅ Mitre-scraped-data.json : Mitigation rules that have been Scraped using the python script
✅ supervised-test-server.py : Creation of AI model based on Supervised Learning with Random Forest Classification and One Hot Encoding
✅ predict.py : Python File that loads the AI model and predicts whether the log should be denied,dropped or accepted
✅ yara-rules.yar : A .yar file that the model uses for prediction. It contains patterns in the log that are potentially malicious
✅ your_model_path.joblib : AI Model 
